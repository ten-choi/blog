#include <iostream>
#include <bitset>
using namespace std;

class Solution
{
public:
    uint32_t reverseBits(uint32_t n)
    {
        uint32_t result = 0;
        for (int i = 0; i < 32; ++i)
        {
            result <<= 1;
            result |= (n & 1);
            n >>= 1;
        }
        return result;
    }
};

int main()
{
    Solution solution;
    uint32_t input = static_cast<uint32_t>(0b11111111111111111111111111111101); // 32비트 이진수 리터럴 사용
    uint32_t result = solution.reverseBits(input);

    cout << "Input (binary):  " << bitset<32>(input) << endl;
    cout << "Output (binary): " << bitset<32>(result) << endl;
    cout << "Output (decimal): " << result << endl;
    return 0;
}
/*
binary로 32비트로 표현된 숫자를 뒤집는 문제이다
그렇기때문에 result에 1칸 left shift를 해주고
1의 부분이

AND (&) → 둘 다 1일 때만 1
*/