#include <iostream>
#include <vector>
using namespace std;

// 1이 몇개인가 세는 문제이다
class Solution
{
public:
    vector<int> countBits(int n)
    {
        vector<int> result(n + 1, 0);
        for (int i = 1; i <= n; ++i)
        {
            result[i] = result[i >> 1] + (i & 1);
        }
        return result;
    }
};

int main(int argc, char const *argv[])
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
/*
홀수 = odd number
짝수 = even number
결국 이게 핵심이다 한칸옮기기
Arithmetic series를 binary로 표시해서 아래 표처럼 보면 left shift할때 해당 배열의 절반값이 나오기때문에 그값에 1의 비트만 구해주고 더하면된다
그리고 1을 계산한다 그렇기때문에 이 코드가 동작한다


i	Binary(i)	i >> 1	Binary(i >> 1)	i & 1	result[i] 계산	1의 개수
0	000	0	000	0	result[0] = 0 + 0	0
1	001	0	000	1	result[1] = result[0] + 1 = 0 + 1	1
2	010	1	001	0	result[2] = result[1] + 0 = 1 + 0	1
3	011	1	001	1	result[3] = result[1] + 1 = 1 + 1	2
4	100	2	010	0	result[4] = result[2] + 0 = 1 + 0	1
5	101	2	010	1	result[5] = result[2] + 1 = 1 + 1	2
6	110	3	011	0	result[6] = result[3] + 0 = 2 + 0	2
7	111	3	011	1	result[7] = result[3] + 1 = 2 + 1	3
*/