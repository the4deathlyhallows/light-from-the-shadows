#include <vector>
#include <unordered_map>
using namespace std;

class Solution {
public:
    vector<int> twoSum(vector<int>& nums, int target) {
        unordered_map<int, int> val_idx;

        for (int i = 0; i < nums.size(); i++) {
            int complement = target - nums[i];

            if (val_idx.find(complement) != val_idx.end()) {
                return {val_idx[complement], i};
            }

            val_idx[nums[i]] = i;
        }

        return {}; // problem guarantees a solution, but keeps compiler happy
    }
};
//

✅ Correct C++ Solution (Using unordered_map)
#include <vector>
#include <unordered_map>
using namespace std;

class Solution {
public:
    vector<int> twoSum(vector<int>& nums, int target) {
        unordered_map<int, int> val_idx;

        for (int i = 0; i < nums.size(); i++) {
            int complement = target - nums[i];

            if (val_idx.find(complement) != val_idx.end()) {
                return {val_idx[complement], i};
            }

            val_idx[nums[i]] = i;
        }

        return {}; // problem guarantees a solution, but keeps compiler happy
    }
};

❌ What Was Wrong in Your Code

You had Python constructs inside C++, which won’t compile:

Python	Why it fails in C++
val_idx = {}	C++ requires a declared type
for i, num in enumerate(nums):	C++ has no enumerate
if target - num in val_idx:	C++ uses .find()
Indentation-based blocks	C++ uses {}
🧠 How This Works (Quick Breakdown)

unordered_map<int, int> stores number → index

For each number:

Compute target - nums[i]

Check if it already exists in the map

If yes → return indices

Otherwise → store current number

⏱ Time Complexity: O(n)
📦 Space Complexity: O(n)

If you want:

a brute-force version

a step-by-step dry run

or to rewrite this using modern C++ (auto, structured bindings)

Just say the word 👌

can you break this down so i understand

Absolutely — let’s break this down slowly and clearly, line by line, so it clicks, not just “works”.

We’ll use the final C++ version, then explain what each part is doing and why.

🔢 The Problem (Plain English)

You’re given:

A list of numbers: nums

A number: target

You must:
➡️ Find two different numbers in nums that add up to target
➡️ Return their indices

Example:

nums = [2, 7, 11, 15]
target = 9


Answer:

[0, 1]   // because 2 + 7 = 9

✅ The Code We’re Explaining
vector<int> twoSum(vector<int>& nums, int target) {
    unordered_map<int, int> val_idx;

    for (int i = 0; i < nums.size(); i++) {
        int complement = target - nums[i];

        if (val_idx.find(complement) != val_idx.end()) {
            return {val_idx[complement], i};
        }

        val_idx[nums[i]] = i;
    }

    return {};
}

🧠 Key Idea (THIS is the insight)

Instead of checking every pair (slow),
we remember what we’ve already seen and look up the missing number instantly.

This is why we use a hash map.

🧰 Line-by-Line Breakdown
1️⃣ Create a Hash Map
unordered_map<int, int> val_idx;


This stores:

value → index


Example while running:

2 → 0
7 → 1


Why?
➡️ So we can check in O(1) time if a number already exists.

2️⃣ Loop Through the Array
for (int i = 0; i < nums.size(); i++) {


We go through each number once, left to right.

i = index
nums[i] = current number

3️⃣ Compute the Missing Number
int complement = target - nums[i];


This answers the question:

“What number do I need to pair with nums[i] to reach target?”

Example:

target = 9
nums[i] = 7
complement = 2

4️⃣ Check If We’ve Seen That Number Before
if (val_idx.find(complement) != val_idx.end()) {


This means:

“Have I already seen the number I need?”

If YES:
➡️ We found the two numbers that sum to target.

5️⃣ Return the Indices
return {val_idx[complement], i};


Why this order?

val_idx[complement] → index of the first number

i → index of the current number

Example:

[0, 1]

6️⃣ If Not Found, Remember This Number
val_idx[nums[i]] = i;


This says:

“I didn’t find a match yet — store this number for later.”

So future numbers can match against it.

🔄 Full Walkthrough Example
Input
nums = {2, 7, 11, 15}
target = 9

Step	i	nums[i]	complement	Map	Result
1	0	2	7	{}	store 2
2	1	7	2	{2→0}	FOUND

Return:

[0, 1]

⏱ Why This Is Fast
Approach	Time
Brute force (nested loops)	O(n²)
Hash map (this solution)	O(n)

That’s why this is the interview answer.

🧩 Why Your Python Logic Was Actually RIGHT

You already had the correct algorithm:

if target - num in val_idx:


You just needed the C++ syntax equivalent.

So mentally:

You already understood the logic ✅

You were just mixing languages ❌

✅ Mental Model to Remember

For each number, ask:
“Have I already seen the number that completes the target?”

If yes → done
If no → save it for later

If you want next:

🔁 Same logic rewritten Python vs C++ side by side

🧠 A version that avoids hash maps

💡 Interview explanation script (what to say out loud)

Just tell me 👍

ChatGPT can make mistakes. Check important info.
