#ifndef SUBSTRINGUTILS_HPP
#define SUBSTRINGUTILS_HPP


#include <cstring>
#include <limits.h>
#include <vector>
#include <string>

#define U_CHAR_MAX1 (UCHAR_MAX + 1)
#define NULL_SYMBOL 0x00

int custom_str_str(const unsigned char * str1, const unsigned char * str2, size_t slen);

typedef std::vector<size_t> occtable_type;
typedef std::vector<size_t> skiptable_type;

const occtable_type create_occ_table(const unsigned char* needle, size_t needle_length);

const skiptable_type create_skip_table(const unsigned char* needle, size_t needle_length);

size_t backwards_match_len(
    const unsigned char* ptr1,
    const unsigned char* ptr2,
    size_t strlen,
    size_t maxlen,
    size_t minlen);

size_t search_boyer_moore(const unsigned char* haystack, size_t haystack_length,
    const occtable_type& occ,
    const skiptable_type& skip,
    const unsigned char* needle,
    const size_t needle_length);

int boyer_moore(const std::string &needle, const std::string &haystack);

int knuth_morris_pratt(const std::string &text, const std::string &pattern);

#endif

