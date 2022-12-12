#include <iostream>
#include <cmath>
#include <unistd.h>
#include <sys/mman.h>
#include <cstring>

#define MAXSIZE pow(10, 8)
#define BIN 128
#define _128KB_ 128*1024
#define KB 1024


enum freeResults {
    BETWEEN_TWO_FREED, ONLY_RIGHT_IS_FREED, ONLY_LEFT_IS_FREED, NO_NEIGHBOR_IS_FREE
};

class MetaDataNode {
public:
    explicit MetaDataNode(size_t size) : size(size) {}

    size_t size;
    bool is_free = false;
    MetaDataNode *prev = nullptr;
    MetaDataNode *next = nullptr;
    MetaDataNode *hist_prev = nullptr;
    MetaDataNode *hist_next = nullptr;
};
MetaDataNode* map_head = nullptr;
size_t map_allocate_blocks = 0;
size_t map_allocated_bytes = 0;
size_t map_meta_data_bytes=0;
///////////////////////////////////////////////
MetaDataNode *meta_hist[BIN] = {nullptr};
#define META_SIZE sizeof(MetaDataNode)


MetaDataNode *head = nullptr;
size_t free_blocks_num = 0; // returns the number of allocated blocks tht are currently free
size_t free_bytes_num = 0; // returns the number of free bytes currently
size_t num_allocated_blocks = 0; //
size_t num_allocated_bytes = 0;
size_t num_meta_data_bytes = 0;


class MallocList {
public:


    static void updateAllocationResults(size_t size, bool reuse);
    void updateChallenge3(size_t old_size ,size_t new_size);
    static void* add(size_t siz);

    static void updateDeallocateResults(size_t size);

    static void free(intptr_t ptr);


};

///////////////////////////////////////////////
MallocList* memory_manage = (MallocList*) sbrk(sizeof(MallocList));

//////////////////////////////////////////////
bool tryToSplit(MetaDataNode *meta, size_t size,bool is_realloc, bool dont_add = false);

void addToHist(MetaDataNode *to_add) {
    unsigned long i = to_add->size / KB;
    MetaDataNode *check = meta_hist[i];
    if (!check) {
        to_add->hist_next = nullptr;
        to_add->hist_prev = nullptr;
        meta_hist[i] = to_add;
        return;
    }
    if (check->size > to_add->size) {
        meta_hist[i] = to_add;
        to_add->hist_next = check;
        to_add->hist_prev = nullptr;
        check->hist_prev = to_add;
        return;
    }
    while ((check->hist_next) && (check->hist_next->size <= to_add->size))
        check = check->hist_next;
    while ((check->hist_next) && ((unsigned long) check->hist_next <= (unsigned long) to_add))
        check = check->hist_next;
    if (check->hist_next) {
        MetaDataNode *next = check->hist_next;
        check->hist_next = to_add;
        to_add->hist_next = next;
        to_add->hist_prev = check;
        next->hist_prev = to_add;
        return;
    }
    check->hist_next = to_add;
    to_add->hist_prev = check;
    to_add->hist_next = nullptr;
}

void removeFromHist(MetaDataNode *to_delete) {
    if(!to_delete)
        return;
    if ((!to_delete->hist_prev) && (!to_delete->hist_next))
        meta_hist[to_delete->size / KB] = nullptr;

    if ((to_delete->hist_prev) && (!to_delete->hist_next))
        to_delete->hist_prev->hist_next = nullptr;

    if ((!to_delete->hist_prev) && (to_delete->hist_next))
        to_delete->hist_next->hist_prev = nullptr;

    if ((to_delete->hist_prev) && (to_delete->hist_next)) {
        to_delete->hist_prev->hist_next = to_delete->hist_next;
        to_delete->hist_next->hist_prev = to_delete->prev;
    }
}

bool allFullExceptLast (size_t size) {
    bool encountered_free_last = false;
    MetaDataNode *ptr = nullptr;
    for (unsigned long i = 0; i < 128; i++) {
        ptr = meta_hist[i];
        while (ptr) {
            if (ptr->is_free && !encountered_free_last && ptr->size >= size) {
                encountered_free_last = true;
                ptr = ptr->hist_next;
                continue;
            }
            if (ptr->is_free && encountered_free_last)
                return false;
            ptr = ptr->hist_next;
        }
    }
    return true;
}

MetaDataNode *histGetFirstFitBlock(size_t size) {
    MetaDataNode *to_ret = nullptr;
    bool full_not_last = allFullExceptLast(size);
    for (unsigned long index = 0; index < 128; index++) {
        to_ret = meta_hist[index];
        while (to_ret) {
            if (to_ret->is_free && full_not_last) {
                return to_ret;
            }
            if (to_ret->size >= size && to_ret->is_free) {
                return to_ret;
            }
            to_ret = to_ret->hist_next;
        }
    }
    return nullptr;
}

void MallocList::updateAllocationResults(size_t size, bool reuse) {
    if(!reuse) {
        num_allocated_blocks++;
        num_allocated_bytes += (size); // todo if have to add meta size
        num_meta_data_bytes += META_SIZE;
    }else {
        free_blocks_num--;
        free_bytes_num -= (size);
    }
}


MetaDataNode *getLastInList(MetaDataNode *MD_head) {
    if (!MD_head)
        return MD_head;
    MetaDataNode *ptr = MD_head;
    while (ptr->next) {
        ptr = ptr->next;
    }
    return ptr;
}

void *allocateAcordingToSize(size_t size) {
    if (size >= _128KB_) {
        return mmap(nullptr, size + META_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }
    return sbrk(size + META_SIZE);
}


freeResults freeHelper(MetaDataNode *node) {
    if ((node->prev) && (node->next)) {
        if ((node->prev->is_free) && (node->next->is_free))
            return BETWEEN_TWO_FREED;
        if ((node->prev->is_free) && (!node->next->is_free))
            return ONLY_LEFT_IS_FREED;
        if (!(node->prev->is_free) && (node->next->is_free))
            return ONLY_RIGHT_IS_FREED;
        return NO_NEIGHBOR_IS_FREE;
    }
    if ((!node->prev) && (node->next)) {
        if (node->next->is_free)
            return ONLY_RIGHT_IS_FREED;
        return NO_NEIGHBOR_IS_FREE;
    }
    if ((node->prev) && (!node->next)) {
        if (node->prev->is_free)
            return ONLY_LEFT_IS_FREED;
        return NO_NEIGHBOR_IS_FREE;
    }
    return NO_NEIGHBOR_IS_FREE;
}


void mergeFreedBlocks(MetaDataNode *meta, freeResults res) {

    MetaDataNode *left = meta->prev;
    MetaDataNode *right = meta->next;
    if (res == NO_NEIGHBOR_IS_FREE) {
        addToHist(meta);
        return;
    }
//todo update freelist
    if (res == ONLY_LEFT_IS_FREED) {

        left->size += meta->size + META_SIZE;
        left->next = meta->next;
        if (meta->next)
            meta->next->prev = left;
        addToHist(left);
        free_bytes_num += META_SIZE;
    }
    if (res == ONLY_RIGHT_IS_FREED) {
        meta->size += right->size + META_SIZE;
        meta->next = right->next;
        if (right->next)
            right->next->prev = meta;
        addToHist(meta);
        free_bytes_num += META_SIZE;
    }
    if (res == BETWEEN_TWO_FREED) {
        left->size += meta->size + right->size + META_SIZE * 2;
        left->next = right->next;
        if (right->next)
            right->next->prev = left;
        addToHist(left);
        free_bytes_num += 2*META_SIZE;
    }
}

void histUpdate(MetaDataNode *meta, freeResults res) {
    MetaDataNode *left = meta->prev;
    MetaDataNode *right = meta->next;
    if (res == NO_NEIGHBOR_IS_FREE)
        return;
    if (res == ONLY_LEFT_IS_FREED) {
        num_meta_data_bytes--;
        free_blocks_num--;
        return removeFromHist(left);
    }
    if (res == ONLY_RIGHT_IS_FREED) {
        num_meta_data_bytes--;
        free_blocks_num--;
        return removeFromHist(right);
    }
    if (res == BETWEEN_TWO_FREED) {
        num_meta_data_bytes -= 2;
        free_blocks_num -= 2;
        removeFromHist(left);
        removeFromHist(right);
    }
}
bool tryToSplit(MetaDataNode* meta , size_t size, bool is_realloc, bool dont_add){
    size_t diff = meta->size - size;
    if ((diff >= 128 + META_SIZE) && (size < meta->size)) { //// challenge 1 (splitting)
        MetaDataNode new_meta = MetaDataNode(meta->size - size - META_SIZE);
        auto oh_yeah = (unsigned long long)meta;
        oh_yeah+=(META_SIZE + size);
        auto helper=(MetaDataNode*)oh_yeah;

        new_meta.prev = meta;
        new_meta.next = meta->next;
        //   MeteDataNode* helper = (MeteDataNode *) new_ptr;
        helper->next = new_meta.next;
        helper->size = new_meta.size;
        helper->prev = new_meta.prev;
        helper->is_free = true; //esaaa
        helper->hist_next = new_meta.hist_next;
        helper->hist_prev = new_meta.hist_prev;
        if(meta->next)
            meta->next->prev = helper;
        meta->next = helper;
        addToHist(helper);
        meta->size = size;
        freeResults res = freeHelper(helper);
        histUpdate(helper, res); /// 288 + 289 + 290 challenge 2(freed block merging)
        mergeFreedBlocks(helper, res);// we are adding to the hist here
        if (is_realloc) {
            free_blocks_num++;
            if (!dont_add)
                free_bytes_num += (diff - META_SIZE);
        }
        else free_bytes_num -= (size + META_SIZE);
        return true;
    }
    return false;
}

void addToMap(void* ptr,size_t size){

    auto helper = (MetaDataNode*)ptr;
    helper->size = size;
    helper->next = nullptr;
    helper->prev = nullptr;
    helper->next = map_head;
    if(map_head)
        map_head->prev = helper;
}
void freeFromMap(MetaDataNode* meta){
    if(!meta)
        return;
    if(meta == map_head)
        map_head = meta->next;
    if(meta->next){
        meta->next->prev = meta->prev;
    }
    if(meta->prev)
        meta->prev->next = meta->next;
}
void* MallocList::add(size_t size) {
    bool was_split = false;
    if (!size)
        return (void*) -1;
    if (size > size_t(MAXSIZE))
        return (void*)-1;

    if(size >= _128KB_){
        auto intptr =    (intptr_t)mmap(nullptr, size + META_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if(intptr == -1)
            return (void*)-1;
        addToMap((void*)intptr,size);
        map_meta_data_bytes +=META_SIZE;
        map_allocated_bytes += size;
        map_allocate_blocks++;
        auto ret_val = (unsigned long long)intptr;
        ret_val+=META_SIZE;
        return (void*)ret_val;

    }
    if (head == nullptr) {
        auto intptr = (intptr_t) allocateAcordingToSize(size); /// challenge 4 (mmap / sbrk)
        if (intptr == -1)
            return (void*)-1;
        updateAllocationResults(size, false);
        head = (MetaDataNode *) intptr;
        *head = MetaDataNode(size);
        auto ret_val = (unsigned long long)intptr;
        ret_val+=META_SIZE;
        return (void*)ret_val;
    }
    MetaDataNode *last = getLastInList(head);
    MetaDataNode *ptr = histGetFirstFitBlock(size);/// challenge 0 (git first fit from hist)
    if (ptr == last) {
        if(last){
            if (last->is_free && (last->size < size)) {/// challenge 3
                removeFromHist(last);
                free_blocks_num--;
                free_bytes_num -= (last->size);
                        auto intptr = (intptr_t) sbrk(size - last->size); //todo  what if last was allocated with mmap ?
                if (intptr == -1)
                    return (void *) -1;
                last->is_free = false;
                memory_manage->updateChallenge3(last->size, size);
                last->size = size;
                auto ret_val = (unsigned long long) last;
                ret_val += META_SIZE;
                return (void *) ret_val;
            }
            else {
                ptr->is_free = false;
                if (ptr->size - size >= 128 + META_SIZE) { //// challenge 1 (splitting)
                    // MeteDataNode new_meta = MeteDataNode(ptr->size - size - META_SIZE);
                    was_split = tryToSplit(ptr,size, false, false);
                }
                if (!was_split)
                    updateAllocationResults(ptr->size, true);
                auto ret_val = (unsigned long long)ptr;
                ret_val+=META_SIZE;
                return (void*)ret_val;
            }
        }
    }else if (ptr) {
        ptr->is_free = false;
        if (ptr->size - size >= 128 + META_SIZE) { //// challenge 1 (splitting)
            // MeteDataNode new_meta = MeteDataNode(ptr->size - size - META_SIZE);
            tryToSplit(ptr,size,false, false);

        }
        updateAllocationResults(ptr->size, true);
        auto ret_val = (unsigned long long)ptr;
        ret_val+=META_SIZE;
        return (void*)ret_val;
    }
    auto intptr = (intptr_t) allocateAcordingToSize(size);
    if (intptr == -1)
        return (void*)-1;
    auto *to_add = (MetaDataNode *) intptr;
    *to_add = MetaDataNode(size);
    last->next = to_add;
    to_add->next = nullptr;
    to_add->prev = last;
    updateAllocationResults(size, false);
    auto ret_val = (unsigned long long)intptr;
    ret_val+=META_SIZE;
    return (void*)ret_val;

}

void MallocList::updateDeallocateResults(size_t size) {
    free_blocks_num++;
    free_bytes_num += (size );

}


void MallocList::free(intptr_t ptr) {
    auto helper = (unsigned long long)ptr;
    helper-=META_SIZE;
    auto *meta = (MetaDataNode*)helper;
    if (meta->is_free) {
        return;
    } else {
        meta->is_free = true;
        free_blocks_num++;
        free_bytes_num += meta->size;
    }
    if(meta->size >= _128KB_){
        map_allocate_blocks--;
        map_allocated_bytes -= meta->size;
        map_meta_data_bytes -=META_SIZE;

        freeFromMap(meta);
        munmap((void*)ptr,meta->size);
    }
    freeResults res = freeHelper(meta);
    histUpdate(meta, res); /// 288 + 289 + 290 challenge 2(freed block merging)
    mergeFreedBlocks(meta, res);// we are adding to the hist here
}

void MallocList::updateChallenge3(size_t old_size ,size_t new_size) {
    num_allocated_bytes += (new_size -old_size ); // todo if have to add meta size
}


void *smalloc(size_t size) {
    if(!size || size > MAXSIZE)
        return nullptr;
    if(size%8)
        size += (8 - (size % 8));
    void* res = memory_manage->add(size);
    if (res == (void*)-1)
        return nullptr;
    return (void *) res;
}

void *scalloc(size_t num, size_t size) {
    if(!size || size > MAXSIZE || num > MAXSIZE)
        return nullptr;
    size_t  to_add = num* size;
    if(to_add%8)
        to_add += (8 - (to_add % 8));
    void* res = memory_manage->add(size * num);
    if (res == (void*)-1)
        return nullptr;
    memset((void *) res, 0, num * size);
    return (void *) res;
}

void sfree(void *p) {
    if (!p)
        return;
    memory_manage->free((intptr_t) p);
}

void* tryLowerMerge(MetaDataNode* meta,size_t size,void* olpb,bool flag){
    if(meta->prev){
        MetaDataNode* prev = meta->prev;
        if((prev->size + meta->size + META_SIZE >= size) && (prev->is_free)){
            prev->size += meta->size + META_SIZE;
            prev->next = meta->next;
            if(meta->next){
                meta->next->prev = prev;
            }
            auto helper = (unsigned long long)prev;
            helper+=META_SIZE;
            memmove((void*)helper,olpb,meta->size);
            prev->is_free= false;
            if(flag)
                tryToSplit(prev,size,true, true);
            return prev;
        }
    }
    return nullptr;
}
void* tryHighMerge(MetaDataNode* meta,size_t size,bool flag){
    if(meta->next) {
        if (meta->next->is_free) {
            MetaDataNode *next = meta->next;
            if (next->size + meta->size + META_SIZE >= size) {
                free_bytes_num -= size - meta->size;
                if (!flag)
                    free_bytes_num -= next->size + meta->size - size;
                meta->size += next->size + META_SIZE;
                meta->next = next->next;
                if (next->next) {
                    next->next->prev = meta;
                }
                //  memmove(meta+META_SIZE,next + META_SIZE,meta->size);
                meta->is_free= false;
                if(flag)
                    tryToSplit(meta,size,true, true);
                return meta;
            }
        }
    }
    return nullptr;
}   //todo: if next==nullptr
void* tryMergeBetween(MetaDataNode* meta,size_t size,void* olpb){
    if(meta->prev && meta->next){
        if((meta->prev->is_free) && (meta->next->is_free)) {
            if (meta->prev->size + meta->next->size + meta->size + 2 * META_SIZE >= size) {
                void* helper= tryLowerMerge(meta, 0,olpb,false);
                tryHighMerge((MetaDataNode*)helper, 0,false);
//                tryToSplit((MetaDataNode*)helper,size, true, true);

                return helper;
            }
        }
    }
    return nullptr;
}
void* tryFindFitBlock(MetaDataNode* meta,size_t size,void* oldp){
    auto res = smalloc (size);
    meta->is_free = true;
    free_blocks_num++;
    free_bytes_num += 2 * meta->size + META_SIZE;
    freeResults free_res = freeHelper(meta);
    printf("%d\n",free_res);
    histUpdate(meta, free_res);
    mergeFreedBlocks(meta,free_res);
    return res;
}
void*tryLowMergeWithNextNull(MetaDataNode* meta,size_t size,void* olpb){
    if(meta->prev){
        MetaDataNode* prev = meta->prev;
        if((meta->next == nullptr) && (prev->is_free)){
            prev->size += meta->size + META_SIZE;
            prev->next = meta->next;
            if(meta->next){
                meta->next->prev = prev;
            }
            auto helper = (unsigned long long)prev;
            helper+=META_SIZE;
            memmove((void*)helper,olpb,meta->size);
            prev->is_free= false;
            if(prev->size < size){
                sbrk(size - prev->size);
                prev->size = size;
            }
            return prev;
        }
    }
    return nullptr;
}
void* tryHighMergeWithNextNull(MetaDataNode* meta,size_t size,void* olpb){
    if(meta->next) {
        if ((meta->next->is_free) &&(meta->next->next == nullptr)) {
            MetaDataNode *next = meta->next;
            MetaDataNode* prev = meta->prev;
            free_bytes_num -= meta->next->size;
            if (meta->prev)
                if (meta->prev->is_free)
                    free_bytes_num -= meta->prev->size;
            meta->size += next->size + META_SIZE;
            meta->next = next->next;
            if (next->next) {
                next->next->prev = meta;
            }
            meta->is_free= false;
            free_blocks_num--;
            if(meta->size < size && meta->prev){
                if (meta->prev->is_free) {
                    prev->size += meta->size + META_SIZE;
                    prev->next = meta->next;
                    if (meta->next) {
                        meta->next->prev = prev;
                    }
                    auto helper = (unsigned long long) prev;
                    helper += META_SIZE;
                    memmove((void *) helper, olpb, meta->size);
                    prev->is_free = false;
                    free_blocks_num--;
                }
                else {
                    sbrk(size - meta->size);
                    meta->size = size;
                    return meta;
                }
            }
            else {
                sbrk(size - meta->size);
                meta->size = size;
                return meta;
            }
            if (prev->size < size) {
                sbrk(size - prev->size);
                prev->size = size;
                return prev;
            }
            return meta;
        }
    }
    return nullptr;
}
void* sreallocChallenges(MetaDataNode* meta,size_t size,void* oldp){
    if(!size || size > MAXSIZE)
        return nullptr;
    if(!oldp)
        return smalloc(size);
    void* res ;
    bool flag = true;
    if(meta->next == nullptr){
        if(meta->prev){
            if(meta->prev->is_free)
                flag = false;
        }
        if(flag){
            if(sbrk(size - meta->size)!=(void*) -1){
                meta->size = size;
                return meta;
            }}
    }
    res = tryLowerMerge(meta,size,oldp,true);
    if(res != nullptr) {
        free_blocks_num--;
        free_bytes_num -= size - meta->size;
        return res;
    }
    res = tryHighMerge(meta,size,true);
    if(res) {

        free_blocks_num--;
        return res;
    }
    res = tryMergeBetween(meta,size,oldp);
    if(res) {
        free_blocks_num -= 2;
        free_bytes_num -= meta->size;
        return res;
    }
    res = tryLowMergeWithNextNull(meta,size,oldp);
    if(res) {
        free_blocks_num--;
        free_bytes_num -= meta->size;
        return res;
    }
    res = tryHighMergeWithNextNull(meta,size,oldp);
    if(res) {
        return res;
    }
    res = tryFindFitBlock(meta,size,oldp);
    if(res){
        sfree(oldp);
        return res;
    }
    return nullptr;
}


void *srealloc(void *oldp, size_t size) {
    if(!size || size > MAXSIZE)
        return nullptr;
    if(!oldp)
        return smalloc(size);
    if(size%8)
        size += (8 - (size % 8));
    auto re = (unsigned long long)oldp;
    re-=META_SIZE;
    auto *meta = (MetaDataNode*) re;
    size_t diff = meta->size - size;
    if ((size <= meta->size) && (meta->size < _128KB_)) {
        if (diff >= 128 + META_SIZE) { //// challenge 1 (splitting)
            tryToSplit(meta,size,true, false);
        }
        return oldp;
    }
    if (meta->size >= _128KB_) {
        void* res = memory_manage->add(size);
        size_t to_add = meta->size;
        if(size < meta->size)
            to_add = size;
        memmove(res,oldp,to_add);
        sfree(oldp);
        if (res == (void*)-1)
            return nullptr;
        return (void *) res;
    }
    /////now lets begin the challenges
    void* res = sreallocChallenges(meta,size,oldp);
    if(!res){
        sfree(oldp);
        void* res = memory_manage->add(size);
        if (res == (void*)-1)
            return nullptr;
        return (void *) res;
    }
//    tryToSplit((MetaDataNode*)res,size,true, false);
    auto ret_val = (unsigned long long)res;
    ret_val+=META_SIZE;
    return (void*) ret_val;
}

size_t _num_free_blocks() {
//    size_t to_ret = 0;
//    if(head){
//        MetaDataNode* ptr = head;
//        while(ptr){
//            if(ptr->is_free)
//                to_ret ++;
//            ptr = ptr->next;
//        }
//    }
    return free_blocks_num;
}

size_t _num_free_bytes() {
//    size_t to_ret = 0;
//    if(head){
//        MetaDataNode* ptr = head;
//        while(ptr){
//            if(ptr->is_free)
//                to_ret += ptr->size;
//            ptr = ptr->next;
//        }
//    }
    return free_bytes_num;
}
size_t _num_allocated_blocks() {
    size_t to_ret = 0;
    if(head){
        MetaDataNode* ptr = head;
        while(ptr){
            //if(!ptr->is_free)
            to_ret ++;
            ptr = ptr->next;
        }
    }
    return to_ret+map_allocate_blocks;
}

size_t _num_allocated_bytes() {
    size_t to_ret = 0;
    if(head){
        MetaDataNode* ptr = head;
        while(ptr){
            to_ret += ptr->size;
            ptr = ptr->next;
        }
    }
    return to_ret+map_allocated_bytes;
}


size_t _num_meta_data_bytes() {
    size_t to_ret = 0;
    if(head){
        MetaDataNode* ptr = head;
        while(ptr){
            to_ret += META_SIZE;
            ptr = ptr->next;
        }
    }
    return to_ret+map_meta_data_bytes;
}

size_t _size_meta_data() {
    return META_SIZE;
}