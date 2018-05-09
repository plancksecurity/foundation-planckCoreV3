Notes:

- TEST_ASSERT is a macro and does not always behave 100% the way you'd expect. Note the following:
	* 1. If used in if/else blocks, make sure the blocks are guarded, or weird things happen.
        * 2. If performing comparisons, please parenthesise liberally - bitwise operations being compared to 0 should always be parenthesised before comparison  
