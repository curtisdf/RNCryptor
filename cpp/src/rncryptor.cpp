#include "tests.h";
#include "base.h";

#include <iostream>
#include <sstream>
using std::stringstream;

int main () {

	RNCryptorTests *tester = new RNCryptorTests();
	tester->run();

	delete tester;
}
