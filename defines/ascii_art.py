#!/usr/bin/env python


class BlockChart():
    def __init__(self):
        self.vertical_separation = 3
        self.horizontal_separation = 3
        self.block_list = []


    def display(

class Block():

    def __init__(self,length,width):
        self.length = length
        self.width = width
        self.horiz_char = "-"
        self.vert_char = "|" 

        self.dcd = None
        


    def connect_horizontal(self,block):

    def extend_vertical(self,block):

    def contract_vertical(self,block): 

    def display(self):
        
    
