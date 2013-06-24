#include "tests.h";
#include "base.h";

int main () {

	RNCryptorTests *tester = new RNCryptorTests();
	tester->run();
	delete tester;
}
