#include <iostream>
#include <vector>
#include <algorithm>

using namespace std;

vector<vector<int>> merge(vector<vector<int>> &intervals)
{
  if (intervals.empty())
    return {};

  sort(intervals.begin(), intervals.end());

  vector<vector<int>> merged;
  merged.push_back(intervals[0]);

  for (int i = 1; i < intervals.size(); ++i)
  {
    vector<int> &last = merged.back();

    if (intervals[i][0] <= last[1])
    {
      last[1] = max(last[1], intervals[i][1]);
    }
    else
    {
      merged.push_back(intervals[i]);
    }
  }

  return merged;
}

int main()
{
  vector<vector<int>> intervals = {
      {1, 3},
      {2, 6},
      {8, 10},
      {15, 18}};

  vector<vector<int>> result = merge(intervals);

  cout << "Merged Intervals:" << endl;
  for (const auto &interval : result)
  {
    cout << "[" << interval[0] << ", " << interval[1] << "]" << endl;
  }
  return 0;
}
/*
It's a simple problem that requires sorting and merging intervals.

*/