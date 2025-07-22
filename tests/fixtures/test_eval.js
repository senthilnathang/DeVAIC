// Test file for Semgrep eval detection
console.log("Starting test");

var userInput = prompt("Enter some code:");
eval(userInput);  // This should be detected by Semgrep

function dangerousFunction(input) {
    eval(input);  // This should also be detected
}

console.log("Test complete");