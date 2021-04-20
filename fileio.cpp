#include <iostream>
#include <fstream>
#include <string.h>

using namespace std;
int train[100];
// char *fileName = ;
int main()
{
	int maxChars=20;
	ifstream fileObject;
	fileObject.open("file.txt");
	cout << "Filing Task\n--------------------\n";
	char c[maxChars];
	while (!fileObject.eof())
	{
		// fileObject.getline(c,maxChars);
		// fileObject.read(c,20)
		fileObject>>c;
		cout<<"read:"<<c<<endl;
		// cin>>t;
	}
	cout<<sizeof(c);
	return 0;
}
