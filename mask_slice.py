# hashcat mask slice program

# ?l -> a-z
# ?u -> A-Z
# ?d -> 0-9
# ?h -> 0-9a-f
# ?H -> 0-9A-F
# ?s ->  !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~

# ?? -> ?


# ?a -> ?l?u?d?s
# ?b -> 0x00 - 0xff

# test -> abcdef,0123,ABC,?l?d,company?u?2?3?1?4?d??

# example : https://hashcat.net/wiki/doku.php?id=mask_attack

# problem: cut off a slice from a mask pool, and the slice is fewer than
# a boundary count (time * speed)

# a slice is composite by multiple masks

# solution: parse, increasing slice mask util it overflows the count (or
# using binary search to find), increasing slice letters util it overflows the count
from functools import reduce
import sys
import argparse
import copy


mask_l_charset = "abcdefghijklmnopqrstuvwxyz"
mask_u_charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
mask_d_charset = "0123456789"
mask_h_charset = "0123456789abcdef"
mask_H_charset = "0123456789ABCDEF"
mask_s_charset = '''!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~'''
mask_question_charset = "?"
mask_a_charset = mask_l_charset + mask_u_charset + mask_d_charset + mask_s_charset
# mask_b_charset = ""
maskchar_charset1 = "abcdef"
maskchar_charset2 = "0123"
maskchar_charset3 = "ABC"
maskchar_charset4 = "ld"
special_letter_qm = '?'  # '??' for literal ?
special_letter_bs = '\\'   # '\,' for literal ','  '\\' for literal '\'


class HcCharType:
    Unset = -1
    MaskChar = 0
    NonEscapedNormalChar = 10
    EscapedNormalChar = 11


class HcChar():
    def __init__(self):
        self.char = ''
        self.charset = []
        self.charset_count = 0
        self.is_mask_boundary = False

    def represent_as_mask():
        pass


class MaskChar(HcChar):
    SpecialLetters = ['?']

    def __init__(self, char, charset):
        self.char = char
        self.charset = charset
        self.charset_count = len(charset)
        self.is_mask_boundary = False

    def __str__(self):
        return str(self.__dict__)

    def represent_as_mask(self):
        return special_letter_qm + self.char


class NormalChar(HcChar):
    def __init__(self, char):
        self.char = char
        self.charset = [char]
        self.charset_count = 1
        self.is_mask_boundary = False

    def __str__(self):
        return str(self.__dict__)

    def represent_as_mask(self):
        raise NotImplementedError()


class EscapeNormalChar(NormalChar):
    SpecialLetters = ['\\', ',']

    def __init__(self, char):
        if char not in EscapeNormalChar.SpecialLetters:
            raise ValueError('illegal EscapeNormalChar:' + char)
        NormalChar.__init__(self, char)

    def represent_as_mask(self):
        return special_letter_bs + self.char


class NonEscapeNormalChar(NormalChar):
    def __init__(self, char):
        NormalChar.__init__(self, char)

    def represent_as_mask(self):
        return self.char


mask_l_charset = "abcdefghijklmnopqrstuvwxyz"
mask_u_charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
mask_d_charset = "0123456789"
mask_h_charset = "0123456789abcdef"
mask_H_charset = "0123456789ABCDEF"
mask_s_charset = r"!\"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"
mask_question_charset = "?"
mask_a_charset = mask_l_charset + mask_u_charset + mask_d_charset + mask_s_charset
# mask_b_charset = ""
# maskchar_charset1 = "abcdef"
# maskchar_charset2 = "0123"
# maskchar_charset3 = "ABC"
# maskchar_charset4 = "ld"
defined_charset_map = [
    # MaskChar('1', maskchar_charset1),
    # MaskChar('2', maskchar_charset2),
    # MaskChar('3', maskchar_charset3),
    # MaskChar('4', maskchar_charset4),
    MaskChar('l', list(mask_l_charset)),
    MaskChar('u', list(mask_u_charset)),
    MaskChar('d', list(mask_d_charset)),
    MaskChar('h', list(mask_h_charset)),
    MaskChar('H', list(mask_H_charset)),
    MaskChar('s', list(mask_s_charset)),
    MaskChar('?', list(mask_question_charset)),
    MaskChar('a', list(mask_a_charset))
]  # noqa


def print_mask(mask):
    for x in mask:
        print(x)


def seperate_charset_and_mask_by_comma(raw_mask, i, out_sep_results, osr_idx, is_literal=False, sep=','):
    '''
    :param raw_mask: a raw-mask contains custom charsets and mask part
    :param i: index of raw_mask
    :param out_sep_results: a 2-d array.
                         out_sep_results[-1]: mask part
                         out_sep_results[:-1]: custom charsets
    '''
    if i == len(raw_mask):
        return

    c = raw_mask[i]

    if not is_literal and c == sep:
        out_sep_results.append('')
        osr_idx = osr_idx + 1
    else:
        if c == '\\':
            is_literal = True
        else:
            is_literal = False
        out_sep_results[osr_idx] += c

    i = i + 1
    seperate_charset_and_mask_by_comma(raw_mask, i, out_sep_results, osr_idx, is_literal)


def find_maskchar_by_letter(c):
    for maskchar in defined_charset_map:
        if maskchar.char == c:
            return copy.deepcopy(maskchar)
    raise Exception('did not find a matched mask char: ' + c)


def decide_special_flag(c):
    if c == special_letter_qm:
        chartype_flag = HcCharType.MaskChar
    # normal char
    elif c == special_letter_bs:
        chartype_flag = HcCharType.EscapedNormalChar
    else:
        chartype_flag = HcCharType.NonEscapedNormalChar
    return chartype_flag


def parse_mask(mask, out_char_list, chartype_flag=HcCharType.Unset):
    '''
    :param mask: list of char (['a', 'b', 'c'])
    :param out_char_list: a list of HcMask (parsed result will be stored)
    :param chartype_flag: HcCharType
    '''
    if len(mask) == 0:
        return
    c = mask.pop(0)
    char_obj = None

    if chartype_flag == HcCharType.Unset:
        chartype_flag = decide_special_flag(c)

        if chartype_flag == HcCharType.NonEscapedNormalChar:
            char_obj = NonEscapeNormalChar(c)
            chartype_flag = HcCharType.Unset
    else:
        if chartype_flag == HcCharType.MaskChar:
            # choose maskChar
            char_obj = find_maskchar_by_letter(c)
            chartype_flag = HcCharType.Unset
        elif chartype_flag == HcCharType.EscapedNormalChar:
            char_obj = EscapeNormalChar(c)
            chartype_flag = HcCharType.Unset
        # elif chartype_flag == HcCharType.NormalNonEscapeChar:
        #     char_obj = NormalNonEscapeChar(c)
        #     chartype_flag = HcCharType.Unset

    if char_obj is not None:
        out_char_list.append(char_obj)
    parse_mask(mask, out_char_list, chartype_flag)


def parse_custom_charset(custom_charset, idx):
    '''
    :return: MaskChar
    '''
    out_char_list = []
    parse_mask(list(custom_charset[idx]), out_char_list)
    # concatenate charsets

    charset = []
    for m in out_char_list:
        charset.extend(m.charset)
    mc = MaskChar(str(idx+1), charset)
    return mc

# calculate mask count


def cal_mask_keycount(mask):
    '''
    :param mask: is a list of char obj (MaskChar or NormalChar)
    :return: an integer of key count
    '''
    return reduce(lambda x, y: x*y, [m.charset_count for m in mask])


# find char boundary between the lower and higher of count_boundary
# Algrithom: increase mask from right to left letter by letter.
# You can even use divide and conquer to speed up

def find_mask_boundary(mask, count_boundary):
    '''
    :param mask: a list of char obj (MaskChar or NormalChar)
    '''
    rev_mask = mask[::-1]
    sub_mask = []
    for m in rev_mask:
        sub_mask.append(m)
        sub_mask_keycount = cal_mask_keycount(sub_mask)
        if sub_mask_keycount > count_boundary:
            m.is_mask_boundary = True
            break


class IncreateMaskOutOfRangeException(Exception):
    pass


def create_singlechar(c):
    '''
    contains EscapeNormalChar MaskChar(?) NonEscapeNormalChar
    but definitely not like MaskChar(d)
    '''
    if c in EscapeNormalChar.SpecialLetters:
        return EscapeNormalChar(c)
    elif c in MaskChar.SpecialLetters:
        return MaskChar(c, [c])
    return NonEscapeNormalChar(c)


def increase_mask_left_part(sp, mask, i):
    '''
    :param sp: start point (a list of HcMask)
    :param mask: (a list of HcMask)
    :param i: index of mask

    i start from biggest to smallest
    '''
    if i < 0:
        raise IncreateMaskOutOfRangeException()
    t = mask[i].charset.index(sp[i].char)
    if t+1 < mask[i].charset_count:
        # current MaskChar can provide a new char
        sp[i] = create_singlechar(mask[i].charset[t+1])
        return
    else:
        # cant provide, move to next MaskChar
        # carry one and reset right part to start point
        sp[i] = create_singlechar(mask[i].charset[0])
        i = i - 1
        increase_mask_left_part(sp, mask, i)


# mask plus one
def increase_mask(start_point, mask):
    '''
    :param start_point: left part (all NormalChar), right part(NormalChar and MaskChar)
    :param mask: a list of char obj (MaskChar or NormalChar)
    :return: a list of char obj like start_point, but 1 bigger than that
    '''
    i = 0
    for m in mask:
        if isinstance(m, MaskChar) and m.is_mask_boundary:
            break
        i = i + 1
    # left part (changed when increasing)
    left_mask = mask[:i+1]
    left_sp = start_point[:i+1]
    # right part (remain the same)
    # right_mask = mask[i+1:]
    right_sp = start_point[i+1:]

    increase_mask_left_part(left_sp, left_mask, i)

    left_sp.extend(right_sp)
    return left_sp


def hccharlist_to_string(mask):
    final = ''
    for m in mask:
        final += m.represent_as_mask()
    return final


def build_start_point_at_mask(mask):
    mask_copy = mask[:]
    for idx in range(len(mask)):
        if isinstance(mask[idx], MaskChar):
            mask_copy[idx] = create_singlechar(mask[idx].charset[0])
        if mask[idx].is_mask_boundary:
            break
    return mask_copy


def expand_slice_util_meet_boundary(result_mask_slice, parsed_char_list, count_boundary):
    count = reduce(lambda x, y: x + y, [cal_mask_keycount(x) for x in result_mask_slice])
    if count >= count_boundary:
        return
    else:
        # increase 1 and add to list

        new_mask = increase_mask(result_mask_slice[-1], parsed_char_list)
        result_mask_slice.append(new_mask)
        expand_slice_util_meet_boundary(result_mask_slice, parsed_char_list, count_boundary)


def mask_slice(test_mask_string, keycount, start=''):
    # speed = 1800
    count_boundary = keycount

    # test_mask_string = "abcdef,0123,ABC,?l?d,company?u?2?3?1?4?d??"
    # test_mask_string = r'??\,\\?l?d,?1???d?d?d'

    out_sep_results = ['']
    seperate_charset_and_mask_by_comma(test_mask_string, 0, out_sep_results, 0)
    custom_charsets_strlist = out_sep_results[:-1]
    mask_str = out_sep_results[-1]

    # list of MaskChar like ?1 ?2
    custom_maskchars = [parse_custom_charset(custom_charsets_strlist, i)
                        for i in range(0, len(custom_charsets_strlist))]
    defined_charset_map.extend(custom_maskchars)

    parsed_char_list = []

    parse_mask(list(mask_str), parsed_char_list, HcCharType.Unset)

    keycount = cal_mask_keycount(parsed_char_list)

    if count_boundary >= keycount:
        print('Current mask cant be sliced because it\'s already the smallest')
        sys.exit()

    result_masks_slice = []

    find_mask_boundary(parsed_char_list, count_boundary)

    # option_specific_start_point = 'companyA0Ae?4?d??'
    option_specific_start_point = start
    sp_mask = None
    if option_specific_start_point:
        p = []
        parse_mask(list(option_specific_start_point), p, HcCharType.Unset)
        result_masks_slice.append(p)
    else:
        sp_mask = build_start_point_at_mask(parsed_char_list)
        result_masks_slice.append(sp_mask)

    try:
        expand_slice_util_meet_boundary(result_masks_slice, parsed_char_list, count_boundary)
    except IncreateMaskOutOfRangeException:
        for x in result_masks_slice:
            print(hccharlist_to_string(x))
        return

    for x in result_masks_slice[:]:
        print(hccharlist_to_string(x))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mask', help='a hashcat mask')
    parser.add_argument('keycount', type=int, help='count of mask slice boundary')
    parser.add_argument('-s', '--start', help='the start point of creating a slice')
    args = parser.parse_args()

    if args.mask and args.keycount:
        mask_slice(args.mask, args.keycount, args.start)
    else:
        print('Invalid option, check -h')


def test():
    mask_slice(r'??\,\\?l?d,?1???d?d?d', 3000)


if __name__ == '__main__':
    # mask_slice.py -s (optional) "000" ?d?d?d 40
    # mask_slice.py "?d?d?d" 10
    # test()
    main()
