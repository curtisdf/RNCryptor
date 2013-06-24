#include "encrypt.h";
#include "decrypt.h";

#include <sstream>
using std::stringstream;

#include <iostream>
using std::cout;
using std::endl;
using std::cin;
using std::getline;

#include <termios.h>

#include "Poco/Util/Application.h"
using Poco::Util::Application;

#include "Poco/Util/Option.h"
using Poco::Util::Option;
using Poco::Util::OptionCallback;

#include "Poco/Util/OptionSet.h"
using Poco::Util::OptionSet;

#include "Poco/Util/HelpFormatter.h"
using Poco::Util::HelpFormatter;

#include "Poco/Util/AbstractConfiguration.h"
using Poco::Util::AbstractConfiguration;

#include "Poco/AutoPtr.h"
using Poco::AutoPtr;

class RNCryptorApp: public Application {
public:
	RNCryptorApp(): _helpRequested(false)
	{
	}

protected:
	void initialize(Application& self)
	{
		loadConfiguration();
		Application::initialize(self);
	}

	void uninitialize()
	{
		Application::uninitialize();
	}

	void reinitialize(Application& self)
	{
		Application::reinitialize(self);
	}

	void defineOptions(OptionSet& options)
	{
		Application::defineOptions(options);

		options.addOption(
			Option("help", "h", "Show help info")
				.required(false)
				.repeatable(false)
				.callback(OptionCallback<RNCryptorApp>(this, &RNCryptorApp::showHelp)));

		/*
		options.addOption(
			Option("define", "D", "define a configuration property")
				.required(false)
				.repeatable(true)
				.argument("name=value")
				.callback(OptionCallback<RNCryptorApp>(this, &RNCryptorApp::handleDefine)));
				*/

		options.addOption(
			Option("config", "c", "Config file (INI format, default none)")
				.required(false)
				.repeatable(true)
				.argument("file")
				.callback(OptionCallback<RNCryptorApp>(this, &RNCryptorApp::setConfig)));

		/*
		options.addOption(
			Option("bind", "b", "bind option value to test.property")
				.required(false)
				.repeatable(false)
				.argument("value")
				.binding("test.property"));
				*/

		options.addOption(
			Option("encrypt", "e", "Encrypt the input")
				.required(false)
				.repeatable(false)
				//.argument("value")
				.callback(OptionCallback<RNCryptorApp>(this, &RNCryptorApp::setActionToEncrypt)));

		options.addOption(
			Option("schema", "s", "Schema version (0-2, default = 2)")
				.required(false)
				.repeatable(false)
				.argument("value")
				.binding("schema"));

		options.addOption(
			Option("decrypt", "d", "Decrypt the input")
				.required(false)
				.repeatable(false)
				.callback(OptionCallback<RNCryptorApp>(this, &RNCryptorApp::setActionToDecrypt)));

		options.addOption(
			Option("password", "p", "Password")
				.required(false)
				.repeatable(false)
				.argument("value")
				.binding("password"));

	}

	void showHelp(const std::string& name, const std::string& value)
	{
		_helpRequested = true;

		HelpFormatter helpFormatter(options());
		helpFormatter.setCommand(commandName());
		helpFormatter.setUsage("OPTIONS");
		helpFormatter.setHeader("Encrypt or decrypt test using Rob Napier's crypto wrappers");
		helpFormatter.format(std::cout);

		stopOptionsProcessing();
	}

	/*
	void handleDefine(const std::string& name, const std::string& value)
	{
		defineProperty(value);
	}
	*/

	void setActionToEncrypt(const std::string& name, const std::string& value)
	{
		defineProperty("action=encrypt");
	}

	void setActionToDecrypt(const std::string& name, const std::string& value)
	{
		defineProperty("action=decrypt");
	}

	void setConfig(const std::string& name, const std::string& value)
	{
		loadConfiguration(value);
	}

	void defineProperty(const std::string& def)
	{
		std::string name;
		std::string value;
		std::string::size_type pos = def.find('=');
		if (pos != std::string::npos)
		{
			name.assign(def, 0, pos);
			value.assign(def, pos + 1, def.length() - pos);
		}
		else {
			name = def;
		}
		config().setString(name, value);
	}

	void setStdinEcho(bool enable = true)
	{
		#ifdef WIN32
			HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
			DWORD mode;
			GetConsoleMode(hStdin, &mode);

			if (!enable) {
				mode &= ~ENABLE_ECHO_INPUT;
			} else {
				mode |= ENABLE_ECHO_INPUT;
			}

			SetConsoleMode(hStdin, mode);

		#else
			struct termios tty;
			tcgetattr(STDIN_FILENO, &tty);
			if (!enable) {
				tty.c_lflag &= ~ECHO;
			} else {
				tty.c_lflag |= ECHO;
			}
			(void) tcsetattr(STDIN_FILENO, TCSANOW, &tty);
		#endif
	}

	string getPassword()
	{
		if (!config().hasProperty("password")) {
			setStdinEcho(false);
			string password;
			cout << "Password: ";
			while(cin) {
				getline(cin, password);
				if (password != "") {
					defineProperty("password=" + password);
					break;
				}
				cout << endl << "Password: ";
			};
			setStdinEcho(true);
		}
		return config().getString("password");
	}

	string getInput(const std::vector<std::string>& args)
	{
		string input;
		if (args.size() > 0) {
			input = args[0];

		} else {
			stringstream inputStream;
			string pipeInput;
			while (getline(cin, pipeInput)) {
				inputStream << pipeInput << endl;
			}
			input = inputStream.str();
		}
		return input;
	}

	int main(const std::vector<std::string>& args)
	{
		if (!_helpRequested)
		{
			string password = getPassword();
			string input = getInput(args);

			string action = config().getString("action");
			if (action == "encrypt") {

				RNEncryptor *encryptor = new RNEncryptor();
				string encryptedBase64;
				if (config().hasProperty("schema")) {
					RNCryptorSchema schema = (RNCryptorSchema)config().getInt("schema");
					encryptedBase64 = encryptor->encrypt(input, password, schema);
				} else {
					encryptedBase64 = encryptor->encrypt(input, password);
				}
				delete encryptor;

				cout << encryptedBase64 << endl;

			} else if (action == "decrypt") {

				RNDecryptor *decryptor = new RNDecryptor();
				string plaintext = decryptor->decrypt(input, password);
				delete decryptor;

				if (plaintext != "") {
					cout << plaintext << endl;
				} else {
					logger().warning("Decryption failed");
				}

			} else {
				logger().warning("Unknown action \"" + action + "\"");
				return Application::EXIT_USAGE;
			}

			/*
			logger().information("Arguments to main():");
			for (std::vector<std::string>::const_iterator it = args.begin(); it != args.end(); ++it)
			{
				logger().information(*it);
			}
			logger().information("Application properties:");
			printProperties("");
			*/



		}
		return Application::EXIT_OK;
	}


	void printProperties(const std::string& base)
	{
		AbstractConfiguration::Keys keys;
		config().keys(base, keys);
		if (keys.empty())
		{
			if (config().hasProperty(base))
			{
				std::string msg;
				msg.append(base);
				msg.append(" = ");
				msg.append(config().getString(base));
				logger().information(msg);
			}
		}
		else
		{
			for (AbstractConfiguration::Keys::const_iterator it = keys.begin(); it != keys.end(); ++it)
			{
				std::string fullKey = base;
				if (!fullKey.empty()) fullKey += '.';
				fullKey.append(*it);
				printProperties(fullKey);
			}
		}
	}

private:
	bool _helpRequested;
};


POCO_APP_MAIN(RNCryptorApp)
