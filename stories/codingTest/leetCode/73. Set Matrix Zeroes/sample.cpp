#include <iostream>
#include <vector>
using namespace std;

void setZeroes(vector<vector<int>> &matrix)
{
  int m = matrix.size();
  int n = matrix[0].size();

  bool firstRowZero = false;
  bool firstColZero = false;

  // Step 1: Check if first row or first column has a zero
  for (int i = 0; i < m; i++)
    if (matrix[i][0] == 0)
      firstColZero = true;

  for (int j = 0; j < n; j++)
    if (matrix[0][j] == 0)
      firstRowZero = true;

  // Step 2: Use first row and column to mark zeroes
  for (int i = 1; i < m; i++)
  {
    for (int j = 1; j < n; j++)
    {
      if (matrix[i][j] == 0)
      {
        matrix[i][0] = 0;
        matrix[0][j] = 0;
      }
    }
  }

  // Step 3: Zero out cells based on marks
  for (int i = 1; i < m; i++)
  {
    for (int j = 1; j < n; j++)
    {
      if (matrix[i][0] == 0 || matrix[0][j] == 0)
        matrix[i][j] = 0;
    }
  }

  // Step 4: Zero out first row and column if needed
  if (firstRowZero)
  {
    for (int j = 0; j < n; j++)
      matrix[0][j] = 0;
  }

  if (firstColZero)
  {
    for (int i = 0; i < m; i++)
      matrix[i][0] = 0;
  }
}

void printMatrix(const vector<vector<int>> &matrix)
{
  for (const auto &row : matrix)
  {
    for (int val : row)
    {
      cout << val << " ";
    }
    cout << endl;
  }
}

int main()
{
  vector<vector<int>> matrix = {
      {1, 1, 1},
      {1, 0, 1},
      {1, 1, 1}};

  cout << "Original matrix:\n";
  printMatrix(matrix);

  setZeroes(matrix);

  cout << "\nModified matrix:\n";
  printMatrix(matrix);

  return 0;
}
