#include "SubStringUtils.hpp"

int custom_str_str(const unsigned char * str1, const unsigned char * str2, size_t slen) {
    unsigned char max_len = 140;
    
    if (!*str2) {
        return -1;
    }

    unsigned char index_header_first[U_CHAR_MAX1];
    unsigned char index_header_end[U_CHAR_MAX1];
    unsigned char last_char[U_CHAR_MAX1];
    unsigned char sorted_index[U_CHAR_MAX1];

    memset(index_header_first, NULL_SYMBOL, sizeof(unsigned char) * U_CHAR_MAX1);
    memset(index_header_end,   NULL_SYMBOL, sizeof(unsigned char) * U_CHAR_MAX1);
    memset(last_char,          NULL_SYMBOL, sizeof(unsigned char) * U_CHAR_MAX1);
    memset(sorted_index,       NULL_SYMBOL, sizeof(unsigned char) * U_CHAR_MAX1);

    unsigned char *cp2 = (unsigned char*) str2;
    unsigned char v;
    unsigned int  len = 0;
    unsigned char current_ind = 1;

    while((v =* cp2) && (len < max_len)) {
        if(index_header_first[v] == 0) {
            index_header_first[v]     = current_ind;
            index_header_end[v]       = current_ind;
            sorted_index[current_ind] = len;
        } else {
            unsigned char last_ind    = index_header_end[v];
            last_char[current_ind]    = last_ind;
            index_header_end[v]       = current_ind;
            sorted_index[current_ind] = len;
        }

        current_ind++;
        len++;
        cp2++;
    }

    if(len > slen) {
        return -1;
    }

    unsigned char *s1, *s2;
    unsigned char *cp     = (unsigned char *) str1 + (len - 1);
    unsigned char *cp_end = cp + slen;

    while (cp < cp_end) {
        if (!*cp) {
            return -1;
        }

        unsigned char ind = *cp;
        if((ind = index_header_end[ind])) {

            do {
                unsigned char pos_in_len = sorted_index[ind];
                s1 = cp - pos_in_len;

                if((unsigned char*)s1 >= str1) {
                    s2 = (unsigned char*) str2;
                    while (*s2 && !(*s1 ^ *s2)) {
                        s1++, s2++;
                    }

                    if (!*s2) {
                        return int((unsigned char*)(cp - pos_in_len) - str1);
                    }
                }
            }
            while(ind = last_char[ind]);
        }
        cp += len;
    }
    return -1;
}

const occtable_type create_occ_table(const unsigned char* needle, size_t needle_length) {
    occtable_type occ(UCHAR_MAX+1, needle_length);

    if(needle_length >= 1) {
        const size_t needle_length_minus_1 = needle_length - 1;
        
        for(size_t a = 0; a < needle_length_minus_1; ++a)
            occ[needle[a]] = needle_length_minus_1 - a;
    }
    
    return occ;
}

const skiptable_type create_skip_table(const unsigned char* needle, size_t needle_length)
{
    skiptable_type skip(needle_length, needle_length);
 
    if(needle_length <= 1) return skip;

    const size_t needle_length_minus_1 = needle_length-1;
 
    std::vector<ssize_t> suff(needle_length);
 
    suff[needle_length_minus_1] = needle_length;
 
    ssize_t f = 0;
    ssize_t g = needle_length_minus_1;
    size_t j = 0;
    for(ssize_t i = needle_length-2; i >= 0; --i)
    {
        if(i > g)
        {
            const ssize_t tmp = suff[i + needle_length_minus_1 - f];
            if (tmp < i - g)
            {
                suff[i] = tmp;
                goto i_done;
            }
        }
        else
            g = i;
 
        f = i;
 
        g -= backwards_match_len(
                needle,
                needle + needle_length_minus_1 - f,
                g+1,
                g+1,
                0
              );
 
        suff[i] = f - g;
    i_done:;
 
        if(suff[i] == i+1) {
            size_t jlimit = needle_length_minus_1 - i;
            while(j < jlimit)
                skip[j++] = jlimit;
        }
    }

    for (size_t i = 0; i < needle_length_minus_1; ++i)
        skip[needle_length_minus_1 - suff[i]] = needle_length_minus_1 - i;
 
    return skip;
}

size_t backwards_match_len(
    const unsigned char* ptr1,
    const unsigned char* ptr2,
    size_t strlen,
    size_t maxlen,
    size_t minlen)
{
    size_t result = minlen;
    while(result < maxlen && ptr1[strlen-1-result] == ptr2[strlen-1-result])
        ++result;
    return result;
}

size_t search_boyer_moore(const unsigned char* haystack, size_t haystack_length,
        const occtable_type& occ,
        const skiptable_type& skip,
        const unsigned char* needle,
        const size_t needle_length) {
    
    if(needle_length > haystack_length) return haystack_length;
 
    if(needle_length == 1) {
        const unsigned char* result =
            (const unsigned char*)std::memchr(haystack, *needle, haystack_length);
        return result ? size_t(result-haystack) : haystack_length;
    }
 
    const size_t needle_length_minus_1 = needle_length - 1;
 
    size_t haystack_position = 0;
    size_t ignore_num = 0, shift = needle_length;
    
    while(haystack_position <= haystack_length-needle_length) {
        size_t match_len;
        
        if(ignore_num == 0) {
            match_len = backwards_match_len(
                needle,
                haystack+haystack_position,
                needle_length,
                needle_length,
                0
               );
            if(match_len == needle_length) return haystack_position;
        } else {
            match_len =
                backwards_match_len(needle, haystack+haystack_position,
                    needle_length,
                    shift,
                    0
                   );
 
            if(match_len == shift) {
                match_len =
                    backwards_match_len(needle, haystack+haystack_position,
                        needle_length,
                        needle_length,
                        shift + ignore_num
                    );
            }
            if(match_len >= needle_length) return haystack_position;
        }
 
        const size_t mismatch_position = needle_length_minus_1 - match_len;
 
        const unsigned char occ_char = haystack[haystack_position + mismatch_position];
 
        const ssize_t bcShift = occ[occ_char] - match_len;
        const size_t gcShift  = skip[mismatch_position];
        const ssize_t turboShift = ignore_num - match_len;
 
        shift = std::max(std::max((ssize_t)gcShift, bcShift), turboShift);
 
        if(shift == gcShift) {
            ignore_num = std::min( needle_length - shift, match_len);
        } else {
            if(turboShift < bcShift && ignore_num >= shift)
                shift = ignore_num + 1;
            ignore_num = 0;
        }
        haystack_position += shift;
    }
    return haystack_length;
}

int boyer_moore(const std::string &haystack, const std::string &needle) {
    const occtable_type occ = create_occ_table(
            (const unsigned char *) needle.c_str(),
            needle.size());
    
    const skiptable_type skip = create_skip_table((const unsigned char *) needle.c_str(), needle.size());
    
    size_t result = (int) search_boyer_moore(
            (const unsigned char *) haystack.c_str(), haystack.size(),
            occ,
            skip,
            (const unsigned char *) needle.c_str(), needle.size());
    if (result == haystack.size()) {
            return -1;
    } else {
            return (int) result;
    }
}

int knuth_morris_pratt(const std::string &text, const std::string &pattern) {
    std::vector <int> T(pattern.size() + 1, -1);
    int matches;

    if(pattern.size() == 0) {
        return -1;
    }

    for(int i = 1; i <= pattern.size(); i++) {
        int pos = T[i - 1];
        while(pos != -1 && pattern[pos] != pattern[i - 1]) pos = T[pos];
        T[i] = pos + 1;
    }

    int sp = 0,
        kp = 0;
    
    while(sp < text.size()) {
        while(kp != -1 && (kp == pattern.size() || pattern[kp] != text[sp])) kp = T[kp];
        
        kp++;
        sp++;
        
        if(kp == pattern.size()) return (sp - pattern.size());
    }

    return -1;
}
