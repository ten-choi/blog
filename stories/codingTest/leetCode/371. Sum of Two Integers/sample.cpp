// Even though it worked correctly with int, using shift operations on int types is generally discouraged in C++ due to potential issues with sign bits and undefined behavior.

class Solution
{
public:
    int getSum(int a, int b)
    {
        while (b != 0)
        {
            unsigned carry = (unsigned)(a & b) << 1;
            // 합인 부분만 1로 만들고 왼쪽시프트를 한다는것은 2진계산에서 자릿수가 넘어가는 부분만 추가한것을 의미한다
            a = a ^ b;
            // 두비트가 다를때 1이되는 xor연산으로는 위에서 2진계산의 자릿수 추가되는 부분이 아닌 부분을 더하는 효과가있다 더해진 숫자를 a에 넣는다
            b = carry;
            // carry는 2진수에서 다음자릿수로 넘어간 부분을 의미하며 이것을 b에 넣고 다시 처음과 같은 방식으로 계산한다 어차피 자릿수올라가는건
            // 한계가 있기때문에 0 이되면 계산이 끝나고 값이 나온다
        }
        return a;
    }
};

/*
+ - 없이 더하기를 하는거다
즉 a와 b를 더하는데 a와 b의 비트가 1인 부분을 더하고
그 비트가 1인 부분을 더한것을 다시 a와 b에 더하는거다
*/