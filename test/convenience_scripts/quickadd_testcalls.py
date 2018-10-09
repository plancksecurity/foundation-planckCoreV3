# very fragile, for Krista's convenience only. DANGER, USE AT OWN RISK.
import sys
import os

calls_added_file = sys.argv[1]
class_name = sys.argv[2]

f = open(calls_added_file, "r")
calls = f.readlines()
f.close()

class_file_path = "src/engine_tests/" + class_name + ".cc"
class_file = open(class_file_path, "r")
class_file_lines = class_file.readlines();
class_file.close();

accumulator = ""
call_part_1 = "    add_test_to_suite(std::pair<std::string, void (Test::Suite::*)()>(string(\""
call_part_3 = "                                                                      static_cast<Func>("

counter = 0
index = 0
for l in class_file_lines:
    if "add_test_to_suite" in l:
        index = counter;
    counter += 1;    

if counter == 0:
    for l in class_file_lines:
        if (l.startswith(class_name)):
            index = counter + 2;
            break;
        counter += 1;
    if (counter == 0):
        os.exit(-1)
else:
    index += 2
            
for c in calls:
    if not c:
        continue
    c = c.rstrip()
    call_part_2 = class_name + "::" + c + "\"),\n"
    call_part_4 = "&" + class_name + "::" + c + ")));\n"

    accumulator += call_part_1 + call_part_2 + call_part_3 + call_part_4
    
class_file_lines.insert(index, accumulator);    

class_file = open(class_file_path, "w")
class_file.writelines(class_file_lines)
class_file.close()

