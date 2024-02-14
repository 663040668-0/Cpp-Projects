#include "iostream"
#include "math.h" // For log() and M_PI
#include "cstdlib" // For system("pause")
using namespace std;

/*
    @pattern a^x = -k

    @condition a > 0, a != 1, k > 0, k != 1

    @result x = (ln(k)/ln(a)) + (PI/ln(a))*i
*/

// Main function entry
int main()
{   
    // Declare what to input and what to solve
    cout<<"a^x = -k"<<endl;
    cout<<"conditions: a > 0, a != 1, k > 0"<<endl;

    // Receive inputs
    double a;
    cout<<"a: "; cin>>a;
    double k;
    cout<<"k: "; cin>>k;

    // Check conditions
    if (!(a > 0 && a != 1 && k > 0))
    {
        cout<<"Error: Input isn't followed the conditions."<<endl;

        // Exit with code -1 (for error)
        return -1;
    }

    // Calculate and display the result
    cout<<"x = "<<(log(k)/log(a))<<" + "<<((double)M_PI/log(a))<<"i"<<endl;

    // Pause for user to read the result
    system("pause");

    // Exit with code 0
    return 0;
}