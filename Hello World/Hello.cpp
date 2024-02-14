#include <iostream> // To output to the console (io = Input & Output)
#include <cstdlib> // To pause the cmd

using namespace std; // Standard namespace (Implicitly includes std::)

// Main function
int main()
{
    // Loop 3 times
    for (int i = 0; i < 3; i++) // i = 0, 1, 2
    {   
        string isS = (i > 0) ? "s" : ""; // Ternary operator if there are more than 1 world
        cout << "Hello " + to_string(i+1) + " World" + isS + "!" << endl; // Concatenate for more the output
    }
    
    cout << "Paused! "; system("pause"); // Display "Press any key to continue . . ." and freeze the cmd

    return 0; // Return 0 because the function required to return an integer
}