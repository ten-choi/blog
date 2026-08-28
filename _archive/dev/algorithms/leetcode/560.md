

Input: nums = [1,2,3], k = 3
Output: 2

```java

class Solution {
    public int subarraySum(int[] nums, int k) {
        // key: 지금까지 나온 prefix sum, value: 그 합이 등장한 횟수
        Map<Integer, Integer> prefixCount = new HashMap<>();
        prefixCount.put(0, 1);  // 빈 prefix — "배열 처음부터 시작하는 부분배열"을 잡기 위해 필수

        int sum = 0;    // 현재까지의 누적합
        int count = 0;  // 정답

        for (int num : nums) {
            sum += num;

            // 핵심: sum - k 라는 prefix가 과거에 있었다면,
            // 그 지점 "다음"부터 현재까지의 합이 정확히 k
            count += prefixCount.getOrDefault(sum - k, 0);

            // 현재 prefix sum을 기록
            prefixCount.merge(sum, 1, Integer::sum);
        }

        return count;
    }
}



 class Solution {
    public int subarraySum(int[] nums, int k) {
        int result = 0;
        int total = 0;
        int i=0;
        int j=0;
        while(i!=nums.length){
            total += nums[i];
            if (total>k) {
                total -= nums[j];
                j++;
                total -= nums[i];
                continue;
            }
            if(total ==k ){
            result++;
            }
            i++;
        }
    }
}
 
```