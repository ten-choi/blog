#include <iostream>
#include <vector>
using namespace std;

class Solution
{
public:
    int missingNumber(vector<int> &nums)
    {
        int n = nums.size();
        // Arithmetic series sum formula
        int expectedSum = n * (n + 1) / 2;
        int actualSum = 0;
        for (int num : nums)
            actualSum += num;
        return expectedSum - actualSum;
    }
};

// Test case
int main()
{
    Solution solution;
    vector<int> nums = {3, 0, 1};
    int result = solution.missingNumber(nums);
    cout << "Missing number is: " << result << endl;
    return 0;
}
/*
Arithmetic series sum formula를 적용하면된다
0부터 n까지의 합은 n(n+1)/2 이다
0이 포함되어있지만 중간에 값 하나가빠져있는 문제이기때문에 size는 그값 그대로 둔다
총합 - 배열의 합
이게 답이다
*/