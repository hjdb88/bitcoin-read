// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_MEMPOOL_ENTRY_H
#define BITCOIN_KERNEL_MEMPOOL_ENTRY_H

#include <consensus/amount.h>
#include <consensus/validation.h>
#include <core_memusage.h>
#include <policy/policy.h>
#include <policy/settings.h>
#include <primitives/transaction.h>
#include <util/epochguard.h>
#include <util/overflow.h>

#include <chrono>
#include <functional>
#include <memory>
#include <set>
#include <stddef.h>
#include <stdint.h>

class CBlockIndex;

// 交易锁定点，交易最后的区块高度和时间
struct LockPoints {
    // Will be set to the blockchain height and median time past
    // values that would be necessary to satisfy all relative locktime
    // constraints (BIP68) of this tx given our view of block chain history
    // 根据我们对区块链历史的看法，将被设置为满足该交易的所有相对锁定时间约束（BIP68）所必需的区块链高度和过去的中值时间值
    int height{0};
    int64_t time{0};
    // As long as the current chain descends from the highest height block
    // containing one of the inputs used in the calculation, then the cached
    // values are still valid even after a reorg.
    // 只要当前链从包含计算中使用的输入之一的最高高度块下降，那么即使在重组之后缓存值仍然有效。
    CBlockIndex* maxInputBlock{nullptr};
};

struct CompareIteratorByHash {
    // SFINAE for T where T is either a pointer type (e.g., a txiter) or a reference_wrapper<T>
    // (e.g. a wrapped CTxMemPoolEntry&)
    template <typename T>
    bool operator()(const std::reference_wrapper<T>& a, const std::reference_wrapper<T>& b) const
    {
        return a.get().GetTx().GetHash() < b.get().GetTx().GetHash();
    }
    template <typename T>
    bool operator()(const T& a, const T& b) const
    {
        return a->GetTx().GetHash() < b->GetTx().GetHash();
    }
};

/** \class CTxMemPoolEntry
 *
 * CTxMemPoolEntry stores data about the corresponding transaction, as well
 * as data about all in-mempool transactions that depend on the transaction
 * ("descendant" transactions).
 *
 * When a new entry is added to the mempool, we update the descendant state
 * (nCountWithDescendants, nSizeWithDescendants, and nModFeesWithDescendants) for
 * all ancestors of the newly added transaction.
 * 
 * CTxMemPoolEntry 存储有关相应交易的数据，以及有关依赖该交易的所有内存池交易（“后代”交易）的数据。
 * 当新条目添加到内存池时，我们会更新新添加交易的所有祖先的后代状态（nCountWithDescendants、nSizeWithDescendants 和 nModFeesWithDescendants）。
 */

class CTxMemPoolEntry
{
public:
    typedef std::reference_wrapper<const CTxMemPoolEntry> CTxMemPoolEntryRef;
    // two aliases, should the types ever diverge
    typedef std::set<CTxMemPoolEntryRef, CompareIteratorByHash> Parents;
    typedef std::set<CTxMemPoolEntryRef, CompareIteratorByHash> Children;

private:
    const CTransactionRef tx; // 交易引用
    mutable Parents m_parents; // 父节点
    mutable Children m_children; // 子节点
    const CAmount nFee;          // 交易费用                 //!< Cached to avoid expensive parent-transaction lookups
    const size_t nTxWeight;                                 //!< ... and avoid recomputing tx weight (also used for GetTxSize())
    const size_t nUsageSize;     // 总内存使用               //!< ... and total memory usage
    const int64_t nTime;         // 进入内存时本地时间        //!< Local time when entering the mempool
    const unsigned int entryHeight; // 进入池时的区块高度     //!< Chain height when entering the mempool
    const bool spendsCoinbase; // 跟踪花费 coinbase 的交易    //!< keep track of transactions that spend a coinbase
    const int64_t sigOpCost;                                //!< Total sigop cost
    CAmount m_modified_fee; // 用于确定区块中挖矿交易的优先级  //!< Used for determining the priority of the transaction for mining in a block
    LockPoints lockPoints;  // 跟踪 tx 最终的高度和时间       //!< Track the height and time at which tx was final

    // Information about descendants of this transaction that are in the
    // mempool; if we remove this transaction we must remove all of these
    // descendants as well.
    // 子孙交易统计
    uint64_t nCountWithDescendants{1}; //!< number of descendant transactions
    uint64_t nSizeWithDescendants;     //!< ... and size
    CAmount nModFeesWithDescendants;   //!< ... and total fees (all including us)

    // Analogous statistics for ancestor transactions
    // 祖先交易统计
    uint64_t nCountWithAncestors{1};
    uint64_t nSizeWithAncestors;
    CAmount nModFeesWithAncestors;
    int64_t nSigOpCostWithAncestors;

public:
    CTxMemPoolEntry(const CTransactionRef& tx, CAmount fee,
                    int64_t time, unsigned int entry_height,
                    bool spends_coinbase,
                    int64_t sigops_cost, LockPoints lp)
        : tx{tx},
          nFee{fee},
          nTxWeight(GetTransactionWeight(*tx)),
          nUsageSize{RecursiveDynamicUsage(tx)},
          nTime{time},
          entryHeight{entry_height},
          spendsCoinbase{spends_coinbase},
          sigOpCost{sigops_cost},
          m_modified_fee{nFee},
          lockPoints{lp},
          nSizeWithDescendants{GetTxSize()},
          nModFeesWithDescendants{nFee},
          nSizeWithAncestors{GetTxSize()},
          nModFeesWithAncestors{nFee},
          nSigOpCostWithAncestors{sigOpCost} {}

    const CTransaction& GetTx() const { return *this->tx; }
    CTransactionRef GetSharedTx() const { return this->tx; }
    const CAmount& GetFee() const { return nFee; }
    size_t GetTxSize() const
    {
        return GetVirtualTransactionSize(nTxWeight, sigOpCost, ::nBytesPerSigOp);
    }
    size_t GetTxWeight() const { return nTxWeight; }
    std::chrono::seconds GetTime() const { return std::chrono::seconds{nTime}; }
    unsigned int GetHeight() const { return entryHeight; }
    int64_t GetSigOpCost() const { return sigOpCost; }
    CAmount GetModifiedFee() const { return m_modified_fee; }
    size_t DynamicMemoryUsage() const { return nUsageSize; }
    const LockPoints& GetLockPoints() const { return lockPoints; }

    // Adjusts the descendant state.
    // 调整后代状态
    void UpdateDescendantState(int64_t modifySize, CAmount modifyFee, int64_t modifyCount);
    // Adjusts the ancestor state
    // 调整祖先状态
    void UpdateAncestorState(int64_t modifySize, CAmount modifyFee, int64_t modifyCount, int64_t modifySigOps);
    // Updates the modified fees with descendants/ancestors.
    // 用后代/祖先更新修改后的费用。
    void UpdateModifiedFee(CAmount fee_diff)
    {
        nModFeesWithDescendants = SaturatingAdd(nModFeesWithDescendants, fee_diff);
        nModFeesWithAncestors = SaturatingAdd(nModFeesWithAncestors, fee_diff);
        m_modified_fee = SaturatingAdd(m_modified_fee, fee_diff);
    }

    // Update the LockPoints after a reorg
    // 更新锁定点
    void UpdateLockPoints(const LockPoints& lp)
    {
        lockPoints = lp;
    }

    uint64_t GetCountWithDescendants() const { return nCountWithDescendants; }
    uint64_t GetSizeWithDescendants() const { return nSizeWithDescendants; }
    CAmount GetModFeesWithDescendants() const { return nModFeesWithDescendants; }

    bool GetSpendsCoinbase() const { return spendsCoinbase; }

    uint64_t GetCountWithAncestors() const { return nCountWithAncestors; }
    uint64_t GetSizeWithAncestors() const { return nSizeWithAncestors; }
    CAmount GetModFeesWithAncestors() const { return nModFeesWithAncestors; }
    int64_t GetSigOpCostWithAncestors() const { return nSigOpCostWithAncestors; }

    const Parents& GetMemPoolParentsConst() const { return m_parents; }
    const Children& GetMemPoolChildrenConst() const { return m_children; }
    Parents& GetMemPoolParents() const { return m_parents; }
    Children& GetMemPoolChildren() const { return m_children; }

    mutable size_t vTxHashesIdx; //!< Index in mempool's vTxHashes
    mutable Epoch::Marker m_epoch_marker; //!< epoch when last touched, useful for graph algorithms
};

#endif // BITCOIN_KERNEL_MEMPOOL_ENTRY_H
