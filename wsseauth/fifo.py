
class Fifo:
    def __init__(self):
        self.front = []
        self.back = []
        self.back_pos = 0
        
    def append(self, data):
        if self.front and (not self.back or self.back_pos == len(self.back)):
            self.back = self.front
            self.back_pos = 0
            self.front = []
        self.front.append(data)

    def empty(self):
        return (len(self.back) - self.back_pos) + len(self.front) == 0

    def top(self):
        if not self.back or self.back_pos == len(self.back):
            return self.front[0]
        return self.back[self.back_pos]

    def pop(self):
        if not self.back or self.back_pos == len(self.back):
            self.back = self.front
            self.back_pos = 0
            self.front = []
            
        out = self.back[self.back_pos]
        self.back_pos += 1
        return out
