#include <iostream>
#include <vector>
#include <unordered_map>
#include <queue>

using namespace std;

// topKFrequent 함수: 가장 자주 등장한 k개의 숫자 반환
vector<int> topKFrequent(vector<int> &nums, int k)
{
    // 1. 숫자별 등장 횟수를 저장할 해시맵
    unordered_map<int, int> freq;
    for (int num : nums)
    {
        freq[num]++;
    }

    // 2. 최소 힙(Min Heap) 선언 (빈도 오름차순)
    auto cmp = [](pair<int, int> &a, pair<int, int> &b)
    {
        return a.second > b.second; // 빈도수가 작은 순으로 정렬
    };
    priority_queue<pair<int, int>, vector<pair<int, int>>, decltype(cmp)> minHeap(cmp);

    // 3. 힙에 k개 요소 유지하면서 삽입
    for (auto &[num, count] : freq)
    {
        minHeap.push({num, count});
        if (minHeap.size() > k)
        {
            minHeap.pop(); // 가장 적게 나온 숫자 제거
        }
    }

    // 4. 결과 벡터에 힙에서 꺼낸 숫자 저장
    vector<int> result;
    while (!minHeap.empty())
    {
        result.push_back(minHeap.top().first);
        minHeap.pop();
    }

    return result;
}

// 메인 함수
int main()
{
    vector<int> nums = {1, 1, 1, 2, 2, 3}; // 입력 배열
    int k = 2;                             // 상위 k개의 요소를 찾기

    vector<int> topK = topKFrequent(nums, k);

    cout << "가장 자주 등장한 " << k << "개의 숫자: ";
    for (int num : topK)
    {
        cout << num << " ";
    }
    cout << endl;

    return 0;
}
