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

말 그대로다
n이 32비트일경우
비트연산 풀이인 만큼 for문에서 그만큼 돌려주면된다
result에 왼쪽비트 한칸 밀어주고 &연산으로 n의 1부분이 1인지 0인지만 판단하고 result에 넣어준다
