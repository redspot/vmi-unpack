/*
 * Copyright (c) 2020 Wilson Martin
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef SEGMENT_TREE_H
#define SEGMENT_TREE_H

#include <stdint.h>
#include <glib.h>

#ifndef max
#define max(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })
#endif

#ifndef min
#define min(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })
#endif

typedef struct {
    uint32_t low;
    uint32_t high;
} segment_key;

typedef struct {
    GTree* t;
    int compare_flag; //controls the tree's compare function
    uint32_t min;
    uint32_t max;
    segment_key* last;   /* set to the last seen node before removal.
                          * once a node is removed, last->(low or high) might
                          * be used as new min/max.
                          */
    segment_key* remove; //set to what we are trying to remove
} SegmentTree;

typedef struct {
  uint32_t point;
  segment_key* found;
} search_data_t;

typedef struct {
  uint32_t flag;
  segment_key* proposed;
  SegmentTree* tree;
} validate_data_t;

//interface
SegmentTree* segment_tree_new(void);
int segment_tree_insert(SegmentTree*, uint32_t, uint32_t, gpointer);
gboolean segment_tree_remove(SegmentTree*, uint32_t, uint32_t);
gboolean segment_tree_point_search(SegmentTree*, uint32_t, segment_key**, gpointer*);
int segment_tree_lookup(SegmentTree*, uint32_t, uint32_t, segment_key**, gpointer*);
void segment_tree_destroy(SegmentTree*);

#endif
