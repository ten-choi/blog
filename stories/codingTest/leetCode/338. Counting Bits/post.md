#include <iostream>
#include <vector>
using namespace std;

class Solution
{
public:
vector<int> countBits(int n)
{
vector<int> result(n + 1, 0);
for (int i = 1; i <= n; ++i)
{
result[i] = result[i >> 1] + (i & 1); // Count bits using dynamic programming
}
return result;
}
};

int main(int argc, char const \*argv[])
{
Solution solution;
int input = 2; // 테스트할 입력값
vector<int> result = solution.countBits(input);
for (int num : result)
{
cout << num << " ";
}
cout << endl;
}

결국 이게 핵심이네 한칸옮기기
i
Binary(i) i >> 1 Binary(i >> 1) i
& 1 result[i] 계산 1의 개수
0 000 0 000 0 result[0] = 0 + 0 0 1 001 0 000 1 result[1] = result[0] + 1 = 0 + 1 1 2 010 1 001 0 result[2] = result[1] + 0 = 1 + 0 1 3 011 1 001 1 result[3] = result[1] + 1 = 1 + 1 2 4 100 2 010 0 result[4] = result[2] + 0 = 1 + 0 1 5 101 2 010 1 result[5] = result[2] + 1 = 1 + 1 2 6 110 3 011 0 result[6] = result[3] + 0 = 2 + 0 2 7 111 3 011 1 result[7] = result[3] + 1 = 2 + 1 3
