<?php


$vectorsDir = __DIR__ . '/../../vectors';
if (!file_exists($vectorsDir)) {
	fputs(STDERR, "ERROR: Vectors dir does not exist: $vectorsDir\n");
	exit(1);
}

function writeLine($fd, $line) {
	fputs($fd, $line . PHP_EOL);
}

function getVectors($absolutePath) {

	if (!file_exists($absolutePath)) {
		throw new Exception('No such file: ' . $absolutePath);
	}

	$index = -1;
	$tests = array();
	$fd = fopen($absolutePath, 'r');
	while (!feof($fd)) {
		$line = trim(fgets($fd));

		if (preg_match("/^\s*(\w+)\s*\:\s*(.*)/", $line, $match)) {
			$key = strtolower($match[1]);
			$value = trim($match[2]);

			if ($key == 'title') {
				$index++;
			}

			$tests[$index][$key] = $value;
		}
	}

	return $tests;
}

$files = glob("$vectorsDir/*");
foreach ($files as $path) {

	$classTemplate = <<<EOF
<?php

require_once __DIR__ . '/VectorBase.php';

/**
 * THIS CLASS IS DYNAMICALLY GENERATED BY ../render-vector-tests.php.
 * IF YOU NEED TO MAKE CHANGES, DO IT IN THAT SCRIPT, OR IN THE VectorBase
 * CLASS WHICH THIS CLASS EXTENDS.  RE-RENDERING THIS CLASS ONLY NEEDS TO
 * HAPPEN WHEN THE CONTENTS OF ../../../vectors/ CHANGE.
 */
class __CLASS_NAME__ extends VectorBase {

	public static function main() {
		\$suite  = new PHPUnit_Framework_TestSuite(get_called_class());
		PHPUnit_TextUI_TestRunner::run(\$suite);
	}
	
__TEST_METHODS__

}

if (!defined('PHPUnit_MAIN_METHOD') || PHPUnit_MAIN_METHOD == '__CLASS_NAME__::main') {
	__CLASS_NAME__::main();
}

EOF;

	$class = $classTemplate;

	$filename = basename($path);
	
	$class = str_replace('__CLASS_NAME__', ucfirst($filename) . 'Vectors', $class);

	
	
	$methodTemplate = <<<EOF
	public function test__METHOD_SUFFIX__() {
__METHOD_BODY__
	}


EOF;

	$methods = array();
	$vectors = getVectors($path);
	foreach ($vectors as $vector) {

		$methodSuffix = str_replace(' ', '', ucwords($vector['title']));
		$method = $methodTemplate;
		$method = str_replace('__METHOD_SUFFIX__', $methodSuffix, $method);

		$lines = array(
			sprintf('$vector = json_decode(\'%s\');', json_encode($vector)),
			sprintf('$this->_run%sTest($vector);', ucfirst($filename))
		);
		$methods[] = str_replace('__METHOD_BODY__', "\t\t" . join("\n\t\t", $lines) . "\n", $method);
	}
	$class = str_replace('__TEST_METHODS__', join('', $methods), $class);

	$classFilePath = __DIR__ . '/tests/' . ucfirst($filename) . 'VectorsTest.php';
	$fd = fopen($classFilePath, 'w+');
	writeLine($fd, $class);
	fclose($fd);
}








