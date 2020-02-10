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

#include <segment_tree.h>
//#include <stdio.h>

/*
 * for a segment tree, the intervals do not overlap
 */
gint segment_tree_compare(gconstpointer first, gconstpointer second, gpointer data)
{
    segment_key* a = (segment_key*) first;
    segment_key* b = (segment_key*) second;
    SegmentTree* tree = (SegmentTree*)data;
    //printf("%s: a={%x:%x} b={%x:%x} min=%x max=%x\n", __func__,
    //    a->low, a->high,
    //    b->low, b->high,
    //    tree->min, tree->max);
    if (tree && tree->compare_flag == 1)
    {
      typeof(a->low) ab_min = min(a->low, b->low);
      typeof(a->high) ab_max = max(a->high, b->high);
      //update each node's min and max
      tree->min = min(tree->min, ab_min);
      tree->max = max(tree->max, ab_max);
      //printf("%s: after update: a={%x:%x} b={%x:%x} min=%x max=%x\n", __func__,
      //    a->low, a->high,
      //    b->low, b->high,
      //    tree->min, tree->max);
    }
    if (tree && tree->compare_flag == -1 && a->low != b->low)
    {
      tree->last = a == tree->remove ? b : a;
      //printf("%s: a={%x:%x} b={%x:%x} last={%x:%x}\n", __func__,
      //    a->low, a->high,
      //    b->low, b->high,
      //    tree->last->low, tree->last->high);
    }
    if (a->low < b->low) //a < b, search left
      return -1;
    if (a->low > b->low) //a > b, search right
      return 1;
    if ( /* a->low == b->low && */ a->high == b->high) //a == b, found it
      return 0;
    return -1; //a->high != b->high, search left even though it will never be found
}

gint point_search(gconstpointer first, gconstpointer second)
{
    segment_key* key = (segment_key*) first;
    search_data_t* data = (search_data_t*) second;
    if (key->low <= data->point && data->point < key->high)
    {
      data->found = key;
      return 0;
    }
    if (data->point < key->low)
      return -1; //search left children
    //else if (data->point >= key->high)
    return 1; //search right children
}

gint validate_insertion(gconstpointer first, gconstpointer second)
{
    segment_key* key = (segment_key*) first;
    validate_data_t* data = (validate_data_t*) second;
    SegmentTree* tree = data->tree;
    typeof(data->proposed) new_key = data->proposed;

    //fail if either new endpoint is within this segment
    if ( (key->low < new_key->high && new_key->high < key->high) /* new_high is in this segment */
        || (key->low < new_key->low && new_key->low < key->high) /* new_low is in this segment */
       )
      goto failed;
    //fail if the new segment engulfs this segment
    if (new_key->low < key->low && key->high <= new_key->high)
      goto failed;
    if (new_key->low == key->low && new_key->high == key->high) //special case: update the existing segment value
      return 0; //stop searching
    //new_high < low
    else if (new_key->high < key->low) //check left children
    {
      if (new_key->low < tree->min && new_key->high >= tree->min) //new segment overlaps something left
        goto failed;
      return -1; //search left children
    }
    else //if (new_key->low >= key->high) //check right children
    {
      if (new_key->high >= tree->max && new_key->low < tree->max) //new segment overlaps something right
        goto failed;
      return 1; //search right children
    }
failed:
    data->flag = 0;
    return 0; //stop searching
}

static void segment_tree_destroy_key(gpointer key) { g_slice_free(segment_key, key); }

SegmentTree* segment_tree_new(void)
{
  SegmentTree* new_tree = g_slice_new(SegmentTree);
  new_tree->compare_flag = 0;
  new_tree->remove = NULL;
  new_tree->last = NULL;
  new_tree->min = ~((uint32_t)0U); // MAX_UINT32
  new_tree->max = 0;
  new_tree->t = g_tree_new_full(segment_tree_compare, new_tree, segment_tree_destroy_key, NULL);
  //printf("%s: min=%x max=%x\n", __func__, new_tree->min, new_tree->max);
  return new_tree;
}

int segment_tree_insert(SegmentTree* tree, uint32_t low, uint32_t high, gpointer data)
{
  if (low >= high) return 0; //bail early if segment is invalid
  segment_key* new_seg = g_slice_new(segment_key);
  new_seg->low = low;
  new_seg->high = high;
  validate_data_t check = {
    .flag = 1U, //set initial value to 1 for valid
    .proposed = new_seg,
    .tree = tree
  };
  g_tree_search(tree->t, validate_insertion, &check);
  if (!check.flag) //overlap detected
  {
    g_slice_free(segment_key, new_seg);
    return 0;
  }
  tree->compare_flag = 1;
  g_tree_insert(tree->t, new_seg, data);
  tree->compare_flag = 0;
  return 1;
}

int segment_tree_lookup(SegmentTree* tree, uint32_t low, uint32_t high, segment_key** pkey, gpointer* pval)
{
  if (low >= high) return 0; //bail early if segment is invalid
  segment_key tmp = { .low = low, .high = high };
  tree->compare_flag = 0;
  return g_tree_lookup_extended(tree->t, &tmp, (gpointer*)pkey, pval);
}

gboolean segment_tree_remove(SegmentTree* tree, uint32_t low, uint32_t high)
{
  if (low >= high) return 0; //bail early if segment is invalid
  segment_key tmp = { .low = low, .high = high };
  tree->remove = &tmp;
  tree->last = NULL;
  tree->compare_flag = -1;
  gboolean rc = g_tree_remove(tree->t, &tmp);
  tree->compare_flag = 0;
  if (rc && (low == tree->min || high == tree->max))
  {
    if (tree->last)
    {
      if (low == tree->min)
        tree->min = tree->last->low;
      else /* if (high == tree->max) */
        tree->max = tree->last->high;
    }
    /* else {} */ //the tree had one node, which we removed
  }
  return rc;
}

gboolean segment_tree_point_search(SegmentTree* tree, uint32_t point, segment_key** pkey, gpointer* pval)
{
  search_data_t data = { .point = point, .found = NULL };
  gpointer val = g_tree_search(tree->t, point_search, &data);
  //g_tree_search returns NULL if not found
  //however, a node value could also be NULL
  //test if data.found is non-NULL
  if (data.found) //segment found
  {
    if (pkey) //they want the key returned
      *pkey = data.found;
    if (pval) //they want the value returned
      *pval = val;
    return 1;
  }
  return 0; //segment not found
}

void segment_tree_destroy(SegmentTree* tree)
{
  g_tree_destroy(tree->t);
  g_slice_free(SegmentTree, tree);
}
