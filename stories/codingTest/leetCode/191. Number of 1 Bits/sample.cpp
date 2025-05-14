class Solution
{
public:
    int hammingWeight(int n)
    {
        int count = 0;
        while (n)
        {
            n = n & (n - 1);
            count++;
        }
        return count;
    }
};
/*
주어진 숫자의 binary값에서 1의 갯수를 세는 문제이다
and연산을해서 둘다 같은부분만 1로 처리하는 방식이다
n-1을 하게되면 가장 오른쪽의 비트 1이 없어지기때문에 1을 셀수가있지 가장오른쪽 비트가 0 인경우에는 그다음 1에서 하나를빼기때문에 계속 1을 빼고 계산하는거야
마지막 n이 1이되는경우 1과 0을 and연산해서 n은 0이되고 마지막카운트 후 와일문을 벗어난다고 볼수있지
*/