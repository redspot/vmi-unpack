/*
 * Copyright (c) 2017 Carter Yagemann
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

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <CUnit/Basic.h>

#include <rekall_parser.h>
#include <dump.h>
#include <segment_tree.h>

#define ADD_SUITE(suite, init, clean) \
  ({ \
     CU_pSuite _new_suite = CU_add_suite(suite, init, clean); \
     if (!_new_suite) { \
       CU_cleanup_registry(); \
       return CU_get_error(); \
     } \
     _new_suite; \
   })

#define ADD_TEST(suite, mesg, func) \
 do{ \
   if (!CU_add_test(suite, mesg, func)) { \
     CU_cleanup_registry(); \
     return CU_get_error(); \
   } \
  }while(0)

/* REKALL */

char *linux_rekall_fp = "test/inputs/linux-rekall-example.json";
char *windows_rekall_fp = "test/inputs/windows-rekall-example.json";

int init_rekall_suite()
{
    if (access(linux_rekall_fp, R_OK) == -1)
    {
        printf("ERROR: Cannot read %s!\n", linux_rekall_fp);
        return -1;
    }
    if (access(windows_rekall_fp, R_OK) == -1)
    {
        printf("ERROR: Cannot read %s!\n", windows_rekall_fp);
        return -1;
    }
    return 0;
}

void test_linux_rekall()
{
    linux_rekall_t rekall;
    CU_ASSERT(parse_rekall_linux(&rekall, linux_rekall_fp) == 1);
    CU_ASSERT(rekall.current_task == 47232);
    CU_ASSERT(rekall.task_struct_comm == 1264);
    CU_ASSERT(rekall.task_struct_pid == 820);
    CU_ASSERT(rekall.task_struct_parent == 840);
    CU_ASSERT(rekall.task_struct_mm == 720);
    CU_ASSERT(rekall.task_struct_tasks == 640);
    CU_ASSERT(rekall.mm_struct_mmap == 0);
    CU_ASSERT(rekall.vm_area_struct_vm_start == 0);
    CU_ASSERT(rekall.vm_area_struct_vm_end == 8);
    CU_ASSERT(rekall.vm_area_struct_vm_next == 16);
    CU_ASSERT(rekall.mm_struct_pgd == 64);
}

void test_windows_rekall()
{
    windows_rekall_t rekall;
    CU_ASSERT(parse_rekall_windows(&rekall, windows_rekall_fp) == 1);
    CU_ASSERT(rekall.kprocess_pdbase == 40);
    CU_ASSERT(rekall.kpcr_prcb == 384);
    CU_ASSERT(rekall.kprcb_currentthread == 8);
    CU_ASSERT(rekall.kthread_process == 528);
    CU_ASSERT(rekall.eprocess_pname == 736);
    CU_ASSERT(rekall.eprocess_pid == 384);
    CU_ASSERT(rekall.eprocess_parent_pid == 656);
    CU_ASSERT(rekall.eprocess_vadroot == 1096);
    CU_ASSERT(rekall.eprocess_objecttable == 512);
    CU_ASSERT(rekall.eprocess_peb == 824);
    CU_ASSERT(rekall.mmvad_leftchild == 8);
    CU_ASSERT(rekall.mmvad_rightchild == 16);
    CU_ASSERT(rekall.mmvad_startingvpn == 24);
    CU_ASSERT(rekall.mmvad_endingvpn == 32);
    CU_ASSERT(rekall.mmvad_controlarea == 72);
    CU_ASSERT(rekall.controlarea_fileobject == 64);
    CU_ASSERT(rekall.fileobject_filename == 88);
    CU_ASSERT(rekall.mmvad_flags == 40);
    CU_ASSERT(rekall.mmvad_flags_sizeof == 8);
    CU_ASSERT(rekall.flags_vadtype_start == 52);
    CU_ASSERT(rekall.flags_vadtype_end == 55);
    CU_ASSERT(rekall.flags_isprivate_start == 63);
    CU_ASSERT(rekall.flags_isprivate_end == 64);
    CU_ASSERT(rekall.flags_protection_start == 56);
    CU_ASSERT(rekall.flags_protection_end == 61);
    CU_ASSERT(rekall.peb_imagebaseaddress == 16);
}

/* DUMP */

void test_compare_hashes_dump()
{
    // hash_a == hash_b != hash_c != hash_d
    unsigned char hash_a[] = "AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD";
    unsigned char hash_b[] = "AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD";
    unsigned char hash_c[] = "AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDI";
    unsigned char hash_d[] = "IAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD";

    CU_ASSERT(compare_hashes(hash_a, hash_b) == 0);
    CU_ASSERT(compare_hashes(hash_b, hash_c) != 0);
    CU_ASSERT(compare_hashes(hash_b, hash_d) != 0);
}

/* SegmentTree */
SegmentTree *test_tree = NULL;
char *value1 = NULL, *value2 = NULL;
const char* value_insert = "insert";
const char* value_update = "update";

int init_segment_tree(void)
{
  test_tree = segment_tree_new();
  value1 = g_slice_alloc(32);
  strcpy(value1, value_insert);
  value2 = g_slice_alloc(32);
  strcpy(value2, value_update);
  return 0;
}

int clean_segment_tree(void)
{
  segment_tree_destroy(test_tree);
  g_slice_free1(32, value1);
  g_slice_free1(32, value2);
  return 0;
}

gboolean show_segment(gpointer key, gpointer value, gpointer data) {
  segment_key *skey = (segment_key*)key;
  SegmentTree* tree = (SegmentTree*)data;
  printf("low=%x high=%x min=%x max=%x\n", skey->low, skey->high, tree->min, tree->max);
  return 0;
}

void test_tree_bad_length()
{
  CU_ASSERT_FALSE(segment_tree_insert(test_tree, 10, 1, NULL));
}

void test_tree_zero_length()
{
  CU_ASSERT_FALSE(segment_tree_insert(test_tree, 1, 1, NULL));
}

void test_tree_insertion()
{
  CU_ASSERT(segment_tree_insert(test_tree, 0x6000, 0x8000, value1)); //root
  CU_ASSERT(segment_tree_insert(test_tree, 0x1000, 0x5000, NULL)); //left
  CU_ASSERT(segment_tree_insert(test_tree, 0x8100, 0x9000, NULL)); //right
  //g_tree_foreach(test_tree->t, show_segment, test_tree);
}

void test_tree_lookup()
{
  segment_key *key = NULL;
  gpointer val = NULL;
  CU_ASSERT(segment_tree_lookup(test_tree, 0x6000, 0x8000, &key, &val));
  if (key)
    { CU_ASSERT(key->low == 0x6000 && key->high == 0x8000); }
  else
    CU_FAIL("returned key is NULL");
  if (val)
    { CU_ASSERT_STRING_EQUAL(val, value_insert); }
  else
    CU_FAIL("returned val is NULL");
  //printf("\n");
  //g_tree_foreach(test_tree->t, show_segment, test_tree);
}

void test_tree_overlapping()
{
  //endpoint in segment
  CU_ASSERT_FALSE(segment_tree_insert(test_tree, 0x1100, 0x5500, NULL));
  CU_ASSERT_FALSE(segment_tree_insert(test_tree, 0x5700, 0x7000, NULL));
  CU_ASSERT_FALSE(segment_tree_insert(test_tree, 0x1100, 0x2000, NULL));

  //overlap right
  CU_ASSERT_FALSE(segment_tree_insert(test_tree, 0x8000, 0xa000, NULL));

  //overlap left
  CU_ASSERT_FALSE(segment_tree_insert(test_tree, 0x900, 0x5500, NULL));

  //segment engulfs another
  CU_ASSERT_FALSE(segment_tree_insert(test_tree, 0x5700, 0x8100, NULL));

  //update existing node
  gpointer val = NULL;
  CU_ASSERT(segment_tree_insert(test_tree, 0x6000, 0x8000, value2));
  CU_ASSERT(segment_tree_lookup(test_tree, 0x6000, 0x8000, NULL, &val));
  CU_ASSERT_STRING_EQUAL(val, value_update);

  CU_ASSERT(segment_tree_lookup(test_tree, 0x1000, 0x5000, NULL, &val));
  if (val)
    { CU_ASSERT_STRING_EQUAL(val, value_insert); }
  else
    CU_PASS("returned val is NULL");
}

void test_tree_search_existent()
{
  segment_key *key1 = NULL, *key2 = NULL;
  gpointer val = NULL;
  CU_ASSERT(segment_tree_point_search(test_tree, 0x1627, &key1, NULL));
  CU_ASSERT(segment_tree_point_search(test_tree, 0x19a2, &key2, NULL));
  CU_ASSERT(key1 && key2 && key1 == key2);

  CU_ASSERT(segment_tree_point_search(test_tree, 0x6000, &key1, &val));
  CU_ASSERT(key1->high == 0x8000);
  CU_ASSERT_STRING_EQUAL(val, value_update);
  //printf("\n");
  //g_tree_foreach(test_tree->t, show_segment, test_tree);
}

void test_tree_search_nonexistent()
{
  CU_ASSERT_FALSE(segment_tree_point_search(test_tree, 0xdeadbeef, NULL, NULL));
  //printf("\n");
  //g_tree_foreach(test_tree->t, show_segment, test_tree);
}

void test_tree_remove_nonexistent()
{
  CU_ASSERT_FALSE(segment_tree_remove(test_tree, 0xbad, 0xfad));
  CU_ASSERT_FALSE(segment_tree_remove(test_tree, 0xdead, 0xbeef)); //test low > high
  //printf("\n");
  //g_tree_foreach(test_tree->t, show_segment, test_tree);
}

void test_tree_remove_existent()
{
  CU_ASSERT(segment_tree_remove(test_tree, 0x1000, 0x5000));
  //printf("\n");
  //g_tree_foreach(test_tree->t, show_segment, test_tree);
  CU_ASSERT_FALSE(segment_tree_point_search(test_tree, 0x1000, NULL, NULL));
  CU_ASSERT_FALSE(segment_tree_lookup(test_tree, 0x1000, 0x5000, NULL, NULL));
  CU_ASSERT(test_tree->min == 0x6000 && test_tree->max == 0x9000);
}

int main(int argc, char *argv[])
{
    unsigned int fails;
    CU_pSuite pSuiteRekall = NULL;
    CU_pSuite pSuiteDump = NULL;
    CU_pSuite pSuiteTree = NULL;

    if (CUE_SUCCESS != CU_initialize_registry())
        return CU_get_error();

    // Rekall

    pSuiteRekall = ADD_SUITE("Suite_Rekall", init_rekall_suite, NULL);
    ADD_TEST(pSuiteRekall, "test linux rekall", test_linux_rekall);
    ADD_TEST(pSuiteRekall, "test windows rekall", test_windows_rekall);

    // Dump

    pSuiteDump = ADD_SUITE("Suite_Dump", NULL, NULL);
    ADD_TEST(pSuiteDump, "test compare hashes dump", test_compare_hashes_dump);

    // SegmentTree
    CU_pSuite pSuiteTree = NULL;
    pSuiteTree = ADD_SUITE("Suite_SegmentTree", init_segment_tree, clean_segment_tree);
    ADD_TEST(pSuiteTree, "insertion of invalid-length segment", test_tree_bad_length);
    ADD_TEST(pSuiteTree, "insertion of zero-length segment", test_tree_zero_length);
    ADD_TEST(pSuiteTree, "insertion of new segment", test_tree_insertion);
    ADD_TEST(pSuiteTree, "lookup of existing key/val", test_tree_lookup);
    ADD_TEST(pSuiteTree, "insertion of overlapping segment", test_tree_overlapping);
    ADD_TEST(pSuiteTree, "search for existent segment", test_tree_search_existent);
    ADD_TEST(pSuiteTree, "search for non-existent segment", test_tree_search_nonexistent);
    ADD_TEST(pSuiteTree, "removal of non-existent segment", test_tree_remove_nonexistent);
    ADD_TEST(pSuiteTree, "removal of existent segment", test_tree_remove_existent);

    CU_basic_set_mode(CU_BRM_NORMAL);
    CU_basic_run_tests();
    fails = CU_get_number_of_tests_failed();
    CU_cleanup_registry();
    if (fails > 0)
        return -1;
    return 0;
}
