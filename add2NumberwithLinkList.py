import pdb
class node(object):
    '''
    Create a empty Node
    '''

    def __init__(self):
          self.data = None
          self.next = None

class List(object):
    '''
    Below will create the link List
    and the methods
    '''

    def __init__(self):
        self.curr_node = None

    def addNumber(self,data):
        new_node = node()
        new_node.data = data
        new_node.next = self.curr_node
        self.curr_node = new_node

    def display(self):
        node = self.curr_node
        while node:
            print node.data
            node = node.next

    def getCurrentNode(self):
        return self.curr_node

class Solution(object):
    '''
    Input : 2 Link List
    Creates a new link list with linear addition of 2 input link list
    '''

    def addList(self,l1,l2):

        L3 = List()
        ptr1 = l1.getCurrentNode()
        ptr2 = l2.getCurrentNode()

        while ptr1 and ptr2:

            value = ptr1.data + ptr2.data
            ptr1 = ptr1.next
            ptr2 = ptr2.next
            L3.addNumber(value)

        return L3.display()




LL = List()
LL.addNumber(2)
LL.addNumber(4)
LL.addNumber(3)

LL1 = List()
LL1.addNumber(5)
LL1.addNumber(6)
LL1.addNumber(4)


print Solution().addList(LL,LL1)
