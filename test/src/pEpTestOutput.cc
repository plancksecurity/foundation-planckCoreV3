#include <cpptest.h>
#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <cstring>

#include "pEpTestOutput.h"
using namespace std;

namespace Test {
	pEpTestOutput::pEpTestOutput() : _total_failed(0), _total_tests(0) {}
    
    void pEpTestOutput::outputCorrectPercentage(int num_tests, int failures, int width) {
        cout << setw(width);
        if (num_tests) {
            double percentage = ((num_tests - failures) / (double)num_tests) * 100;
            cout << std::fixed << setprecision(1) << percentage << "\%"; 
        }
        else 
            cout << "N/A";
    }
    	
	void pEpTestOutput::finished(int tests, const Test::Time& time) {
        cout << huge_sepline << endl;
        string header = "FULL TEST RUN RESULTS:";
        cout << alt_sepline << left << setw(header.size()) << header;
        cout << right << setw(56 - header.size()) << "+" << endl;
        cout << right << setw(30) << "Number of tests run: " << setw(7) << tests << setw(19) << "+" << endl;
        cout << right << setw(30) << "Tests failed: " << setw(7) << _total_failed << setw(19) << "+" << endl;
        cout << right << setw(30) << "Pass percentage: ";
        outputCorrectPercentage(_total_tests, _total_failed, 7);
        cout << setw(18) << "+" << endl;
        cout << setw(56) << "+" << endl;
        string finalstr = std::to_string(tests) + " tests run in " + std::to_string(time.seconds()) + "." + std::to_string(time.microseconds()) + " seconds.";
        int remlen = 56 - finalstr.size();
        cout << left << setw(finalstr.size()) << finalstr << right << setw(remlen) << "+" << endl;
        cout << alt_sepline << endl;
	}
	
	void pEpTestOutput::suite_start(int tests, const string& name) {
        _suite_failed = 0;
        _suite_name = name;
        _suite_total = 0;
        if (tests > 0) {
            cout << endl << huge_sepline;
            cout << "BEGIN TEST SUITE: " << name << endl << endl;
        }
	}
	
	void pEpTestOutput::suite_end(int tests, const string& name, const Test::Time& time)
	{
        if (tests > 0) {
            cout << endl << "Suite results:" << endl; 
            cout << right << setw(30) << "Number of tests run: " << setw(7) << tests << endl;
            cout << right << setw(30) << "Tests failed: " << setw(7) << _total_failed << endl;
            cout << right << setw(30) << "Pass percentage: ";
            outputCorrectPercentage(_suite_total, _suite_failed, 7);
            cout << endl << endl;
            cout << tests << " tests run in " << time << " seconds." << endl;
            cout << endl;
            cout << "END TEST SUITE: " << name << endl;
        }
	}
    
	void pEpTestOutput::test_start(const std::string& name) {
        _test_name = name;
        cout << med_sepline;
        cout << "Begin test " << name << endl;
        cout << lil_sepline;
        _test_errors.clear();
    }
    void pEpTestOutput::test_end(const string& name, bool ok, const Test::Time&) {
	    if (!ok) {
            _suite_failed++;
            _total_failed++;
            cout << endl << endl << alt_sepline;
            cout << "*** Test " << name << " failed!" << endl;
            vector<Source>::iterator it;
            for (it = _test_errors.begin(); it != _test_errors.end(); it++) {
                Source src = *it;
                cout << lil_sepline;
                cout << left << setw(25) << "*** Assert location: " << src.file() << ":" << src.line() << endl;
                cout << left << setw(25) << "*** Message: " << src.message() << endl;                
            }
            cout << alt_sepline << endl;
        }
        _total_tests++;
        _suite_total++;

        cout << "End test " << name << endl;
        cout << med_sepline;        
	}
	
	void pEpTestOutput::assertment(const Source& s) {
		_test_errors.push_back(s);
	}
}