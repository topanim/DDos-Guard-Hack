from dataclasses import dataclass
from textwrap import dedent

base_command = "set firewall family inet filter"


class Term:
    __num = 0

    def get(self):
        self.__num += 1
        return self.__num


tTerm = Term()


@dataclass
class Line:
    subnet: str
    prefix: str
    dest_ports: str
    protocols: str
    allow_ports: str

    def to_command(self, filterName: str) -> str:
        term1 = tTerm.get()
        term2 = tTerm.get()
        return dedent(f"""
        {base_command} {filterName} term {term1} from source-address 0.0.0.0/0
        {base_command} {filterName} term {term1} from destination-address {subnet[1:]}/{prefix}
        {base_command} {filterName} term {term1} from protocol [{protocols}]
        {base_command} {filterName} term {term1} from destination-port [{dest_ports}]
        {base_command} {filterName} term {term1} from source-port [{allow_ports}]
        {base_command} {filterName} term {term1} then accept
        
        {base_command} {filterName} term {term2} from source-address 0.0.0.0/0
        {base_command} {filterName} term {term2} from destination-address {subnet[1:]}/{prefix}
        {base_command} {filterName} term {term2} then reject
        """)


lines = []
filterName = input("filter name: ")
firstLine = f"set interfaces ge-0/0/2 unit 0 family inet filter input {filterName}"

with open("config.txt", "r") as f:
    config = f.read()

for line in config.split(";"):
    subnet, prefix, dest_ports, protocols, allow_ports = line.split(", ")

    lines.append(
        Line(
            subnet=subnet,
            prefix=prefix,
            dest_ports=dest_ports,
            protocols=protocols,
            allow_ports=allow_ports,
        )
    )

commitLine = "commit"

resultString = firstLine + "\n"
for command in lines:
    resultString += command.to_command(filterName)
resultString += commitLine

with open("../base_filter_config_generated.txt", "w+") as f:
    f.write(resultString)

print(resultString)
