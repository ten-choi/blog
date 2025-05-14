#include <iostream>
#include <vector>
#include <algorithm>
using namespace std;

int coinChange(vector<int> &coins, int amount)
{
  vector<int> dp(amount + 1, amount + 1); // 큰 값으로 초기화
  dp[0] = 0;                              // 0원을 만들기 위한 동전 수는 0

  for (int i = 1; i <= amount; ++i)
  {
    for (int coin : coins)
    {
      if (i - coin >= 0)
      {
        dp[i] = min(dp[i], dp[i - coin] + 1);
      }
    }
  }

  return dp[amount] == amount + 1 ? -1 : dp[amount];
}

int main()
{
  vector<int> coins = {1, 2, 5};
  int amount = 11;

  int result = coinChange(coins, amount);
  cout << "Minimum coins needed: " << result << endl;

  return 0;
}

/*
살짝 빡새서 보류
*/