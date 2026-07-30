# Bundled data

## `eff_long_wordlist.txt`

The EFF "long" diceware wordlist: 7776 words (6^5), giving log2(7776) = 12.925
bits of entropy per word.

- Source: <https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt>
- Author: Joseph Bonneau / Electronic Frontier Foundation
- License: CC-BY-3.0 (<https://creativecommons.org/licenses/by/3.0/us/>)
- Retrieved: 2026-07-30

The original file is tab-separated (`dice-roll<TAB>word`); only the word column
is kept here. Word order is preserved exactly, so an index into this file
corresponds to the original dice roll.

The list is chosen over the shorter EFF lists because longer average word length
buys typo resistance without costing entropy per word, and over Diceware's
original list because it avoids obscure words, punctuation, and character
sequences that are awkward to type on mobile keyboards.
