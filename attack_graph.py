import networkx as nx
import numpy as np
import matplotlib.pyplot as plt

class AttackGraphModeler:
    def __init__(self, topology_file, connections_file):
        self.graph = nx.DiGraph()
        self.topology = self._parse_topology(topology_file)
        self.connections = self._parse_connections(connections_file)
        
    def _parse_topology(self, file_path):

        topology = {}
        with open(file_path, 'r') as f:
            for line in f:
                ip, vulns = line.strip().split(' : ')
                topology[ip] = [v.strip() for v in vulns.split(',')]
        return topology

    def _parse_connections(self, file_path):

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

        # Добавление узлов с уязвимостями
        for ip, vulns in self.topology.items():
            self.graph.add_node(ip, vulnerabilities=vulns)
        
        # Добавление связей
        for router, data in self.connections.items():
            # Связи с другими маршрутизаторами
            for connected_router in data['routers']:
                self.graph.add_edge(router, connected_router)
            
            # Связи с узлами
            for node in data['nodes']:
                access, node_ip = node[0], node[1:].strip()
                if access == '+':
                    self.graph.add_edge(router, node_ip)
        
        return self.graph

    def visualize(self):

        # Кастомное расположение
        pos = {}
        nodes = list(self.graph.nodes())
        
        # Фильтр узлов, чтобы центральный был только один
        center_node = "192.168.134.3"
        circle_nodes = [n for n in nodes if n != center_node]
        
        # Узлы по кругу
        n = len(circle_nodes)
        radius = 8  # Увеличиваем радиус для лучшего отображения
        angle = np.linspace(0, 2*np.pi, n, endpoint=False)
        
        for i, node in enumerate(circle_nodes):
            x = radius * np.cos(angle[i])
            y = radius * np.sin(angle[i])
            pos[node] = (x, y)
        
        # Центральный узел
        pos[center_node] = (0, 0)
        
        # Фигура большего размера
        plt.figure(figsize=(10, 10))
        
        # Рисуем узлы
        nx.draw_networkx_nodes(
            self.graph, pos,
            nodelist=circle_nodes,
            node_color='lightblue',
            node_size=2000,
            edgecolors='black'
        )
        
        # Центральный узел в виде треугольника
        nx.draw_networkx_nodes(
            self.graph, pos,
            nodelist=[center_node],
            node_color='red',
            node_shape='^',
            node_size=3000,
            edgecolors='black'
        )
        
        # Связи и подписи
        nx.draw_networkx_edges(
            self.graph, pos,
            edge_color='gray',
            arrows=True,
            arrowstyle='-|>',
            arrowsize=20
        )
        
        nx.draw_networkx_labels(
            self.graph, pos,
            font_size=12,
            font_weight='bold'
        )
        
        plt.axis('off')
        
        # Фиксируем масштаб осей
        plt.xlim(-radius*1.2, radius*1.2)
        plt.ylim(-radius*1.2, radius*1.2)
        
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