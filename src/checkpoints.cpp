// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/assign/list_of.hpp> // for 'map_list_of()'
#include <boost/foreach.hpp>

#include "checkpoints.h"

#include "txdb.h"
#include "main.h"
#include "uint256.h"


static const int nCheckpointSpan = 5000;

namespace Checkpoints
{
    typedef std::map<int, uint256> MapCheckpoints;

    //
    // What makes a good checkpoint block?
    // + Is surrounded by blocks with reasonable timestamps
    //   (no blocks before with a timestamp after, none after with
    //    timestamp before)
    // + Contains no strange transactions
    //
    static MapCheckpoints mapCheckpoints =
        boost::assign::map_list_of
    (     0, uint256("0x000008cbffa527b5a3b043f28e3707eb5b926cc71d929d69b3c769805d488e22") )
    (     1, uint256("0x0000056e2fe20fe2328e3b002cc19ee49d0cce5f58a1f8837f8174f3f5437c54") )
    (     2, uint256("0x000007dc9694cd8bab31ca9f9be099cdea9614c0cba10a4fef39d063381edfbf") )
    (     3, uint256("0x00000a8f4835e19cabc51d798aa6d1f1954a1bc5172934680ea3cf98f6a218fa") )
    (     4, uint256("0x00000df86d07cd0cca86306f9498fe6bed47bf505f0e7a7f1fe1e57b76be3c04") )
    (     5, uint256("0x00000736e93e4f15f9a9c5c65b1e8bf228f42b3384beacf4028046388666d4f1") )
    (     10, uint256("0x000000814ee4acecdc7fb31942ce2d91de301995cadbaa8477d317e19f191f73") )
    (     15, uint256("0x000003d91e33672c7ba98096b8e22f6744be02a1202c7b2bdc43bd23b0f323e0") )
    (     20, uint256("0x00000a001ca3e6b770af4c50f32b1c6034c2fdb19b693c47570d04dceed7bb97") )
    (     25, uint256("0x000008a8af565376387ee3606ab5f712d7eb260f2ca9b4c59f59742a34acbb84") )
    (     30, uint256("0x000005907e2312b31d1cc090d3eaecfce9eadb8f348abae890bab02e971a0c4d") )
    (     35, uint256("0x0000022826d2c420fe43cc10a4a8f25d2a598b022c98670ba69c41cfb82b70d6") )
    (     40, uint256("0x0000092ba798d69156a776205c0399b835be6906e08faa7c8741e78a21ea70ce") )
    (     45, uint256("0x000000b08299b8e0c2620845d2542c4f107f0886ae18a2aa297d82f99a506972") )
    (     50, uint256("0x000003becf78c6ec422a707f8a9df9c7f529486c328aa28e92dfb039eaaf0eef") )
    (     51, uint256("0x0000062d0409f1be779b29ffc4aa63711a9d0f086c8a352ee62c1a657f1a38ff") )
    ;

    // TestNet has no checkpoints
    static MapCheckpoints mapCheckpointsTestnet;

    bool CheckHardened(int nHeight, const uint256& hash)
    {
        MapCheckpoints& checkpoints = (TestNet() ? mapCheckpointsTestnet : mapCheckpoints);

        MapCheckpoints::const_iterator i = checkpoints.find(nHeight);
        if (i == checkpoints.end()) return true;
        return hash == i->second;
    }

    int GetTotalBlocksEstimate()
    {
        MapCheckpoints& checkpoints = (TestNet() ? mapCheckpointsTestnet : mapCheckpoints);

        if (checkpoints.empty())
            return 0;
        return checkpoints.rbegin()->first;
    }

    CBlockIndex* GetLastCheckpoint(const std::map<uint256, CBlockIndex*>& mapBlockIndex)
    {
        MapCheckpoints& checkpoints = (TestNet() ? mapCheckpointsTestnet : mapCheckpoints);

        BOOST_REVERSE_FOREACH(const MapCheckpoints::value_type& i, checkpoints)
        {
            const uint256& hash = i.second;
            std::map<uint256, CBlockIndex*>::const_iterator t = mapBlockIndex.find(hash);
            if (t != mapBlockIndex.end())
                return t->second;
        }
        return NULL;
    }

    // Automatically select a suitable sync-checkpoint 
    const CBlockIndex* AutoSelectSyncCheckpoint()
    {
        const CBlockIndex *pindex = pindexBest;
        // Search backward for a block within max span and maturity window
        while (pindex->pprev && pindex->nHeight + nCheckpointSpan > pindexBest->nHeight)
            pindex = pindex->pprev;
        return pindex;
    }

    // Check against synchronized checkpoint
    bool CheckSync(int nHeight)
    {
        const CBlockIndex* pindexSync = AutoSelectSyncCheckpoint();
        if (nHeight <= pindexSync->nHeight){
            return false;
        }
        return true;
    }
}
