# AD-OU-Delegation
Using a JSON source file to set and reset ACL delegations for Users, Groups, and Computer objects.

Rought draft of a script that will take input from a golden source JSON file to control the delegation access to specific OUs, groups, ACLs, and objects.

Script is currently written for a scenario, but could be adjust to support a more use cases by changing most of the code to PowerShell modules and functions with parameters.

Scenario are the regions are the scope of where an person is allowed to manage objects such as Users, Groups, and Computers. Naming convention is (4-Letter-Region)-(Access)-(ObjectType) example APAC-A-Users.

Regions such as APAC, EMEA, AMER are examples.

Access Types
============
A = Allow access to basic attributes with low risk such as updating a home address.
S = Allow access to security attributes with medium such as changing an employees id number, managedby, members
P = Allow access to changing ore reset another users password.
L = Allow access to computer object to retrieve the local Builtin\Administrator password of the endpoint

Object types are Computers, Users, and Groups


How code can be massively improved would be to modulize each of the delegation types and add more input into the JSON file such as the AD ACE type such as Create, Delete, Extended of each of the properties removal of all hard coding such as the ifelse statements once each has been modualized.
