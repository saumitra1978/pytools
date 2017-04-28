'''
This is a implementation of double link list using dictinary data structure

'''
import pdb


class dynamic_array(object):

   def __init__(self):
 
    self.num_of_node = 0
    self.curr_node = {
       'data': None,
        'next': None,
        'prev': None
        }

   def addNode(self,data):
      '''
      Add Element to link list
      '''
      self.num_of_node +=1
      new_node = {}
      new_node['data'] = data
      new_node['next'] = self.curr_node
      new_node['prev'] = None
      self.curr_node['prev'] = new_node
      self.curr_node = new_node

   def delNode(self,data):
     '''
     Delete the node from link list
     '''
     node = self.curr_node
     while node:
        #find the node that matches the data prop
        if node['data'] == data:
              #found the node
              print "Found the node"
              prev_node = node['prev']
              next_node = node['next']

              #Now change the references
              prev_node['next'] = next_node
              next_node['prev'] = prev_node

              self.num_of_node -= 1
              return True
        else:
              node = node['next']
     print "Element not found"
     return False 

   def display(self):
      '''
      Display the elements in link list
      '''
      node = self.curr_node
      while node:
          print node['data']
          node = node['next']

   def length(self):
     '''
     Return the length of the link list
     '''
     return self.num_of_node

if __name__ == '__main__':
    obj = dynamic_array()
    obj.addNode(2)
    obj.addNode(3) 
    obj.addNode(200)
    obj.addNode(300) 
    obj.display()
    print "Length of the list is {0}".format(obj.length())
    obj.delNode(200)
    obj.display()
    print "Length of the list is {0}".format(obj.length())

       
   
    

   
