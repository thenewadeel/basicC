#include<iostream>
//#include<stdio.h>
using namespace std;
int train[100];
void populateTrain(){
	for(int i=0;i<100;i++){
		train[i]=1+rand()%50;
	}
}
void showTrain(){
	for(int i=0;i<100;i++){
		cout<<i<<":"<<train[i]<<endl;
	}
}
int conductor(int target){
	for(int i=0;i<100;i++){
		if(train[i]==target){
			return i;
		}
	}
	return -1;
}
int main(){
	int guess;
	populateTrain();
//	showTrain();
	cout<<"\nEnter Guess:";
	cin>>guess;
	int result=conductor(guess);
	if(result!=-1){
		cout<<"Target found at location: "<<result;
	}else{
		cout<<"NOT FOUND";
	}
	return 0;
}
