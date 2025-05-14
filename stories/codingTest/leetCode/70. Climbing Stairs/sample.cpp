#include <iostream>
using namespace std;

int climbStairs(int n)
{
  if (n <= 2)
    return n;

  int first = 1;  // Ways to reach step 1
  int second = 2; // Ways to reach step 2
  int result = 0;

  for (int i = 3; i <= n; ++i)
  {
    result = first + second;
    first = second;
    second = result;
    /*
        f(n) = f(n - 1) + f(n - 2)
        use fibonacci sequence
    */
  }
  return result;
}

int main()
{
  int n = 10;
  cout << "Ways to climb to the top: " << climbStairs(n) << endl;
  return 0;
}

/*
f(n) = f(n - 1) + f(n - 2)
use fibonacci sequence
피보나치는 패턴을 외운다 라는식으로 이해하고 넘어갔다
저 패턴은 일정하며 그렇기에 식을 대입해서 적용했다
*/