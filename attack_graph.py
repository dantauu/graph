import networkx as nx
import numpy as np
import matplotlib.pyplot as plt

class AttackGraphModeler:
    def __init__(self, topology_file, connections_file):
        self.graph = nx.DiGraph()
        self.topology = self._parse_topology(topology_file)
        self.connections = self._parse_connections(connections_file)
        
    def _parse_topology(self, file_path):
        """Чтение файла топологии"""
        topology = {}
        with open(file_path, 'r') as f:
            for line in f:
                ip, vulns = line.strip().split(' : ')
                topology[ip] = [v.strip() for v in vulns.split(',')]
        return topology

    def _parse_connections(self, file_path):
        """Чтение файла связей"""
        connections = {}
        current_router = None
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line.endswith(':'):
                    current_router = line[:-1]
                    connections[current_router] = {'routers': [], 'nodes': []}
                elif line.startswith('>'):
                    connections[current_router]['routers'].append(line[1:].strip())
                elif line.startswith(('+', '-')):
                    connections[current_router]['nodes'].append(line)
        return connections

    def build_graph(self):
        """Построение графа атак"""
        # добавление узлов с уязвимостями
        for ip, vulns in self.topology.items():
            self.graph.add_node(ip, vulnerabilities=vulns)
        
        # добавление связей
        for router, data in self.connections.items():
            # связи с другими маршрутизаторами
            for connected_router in data['routers']:
                self.graph.add_edge(router, connected_router)
            
            # связи с узлами
            for node in data['nodes']:
                access, node_ip = node[0], node[1:].strip()
                if access == '+':
                    self.graph.add_edge(router, node_ip)
        
        return self.graph

    def visualize(self):
        """Визуализация графа"""
        pos = nx.spring_layout(self.graph)
        nx.draw(
            self.graph, pos, 
            with_labels=True, 
            node_color='lightblue', 
            edge_color='gray',
            node_size=2000,
            font_size=8
        )
        plt.title("Attack Graph")
        plt.show()

if __name__ == "__main__":
    # модели
    modeler = AttackGraphModeler(
        topology_file="topology.txt",
        connections_file="connections.txt"
    )
    
    # граф
    attack_graph = modeler.build_graph()
    
    # визуал
    modeler.visualize()
    
   # анализ
    print("Узлы графа:", attack_graph.nodes(data=True))
    print("Рёбра графа:", attack_graph.edges())