import pickle
import re
import numpy as np
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from colorama import Fore
from urllib.parse import urlparse
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, classification_report, accuracy_score
from sklearn.neural_network import MLPClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, AdaBoostClassifier, ExtraTreesClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import SGDClassifier
from sklearn.naive_bayes import GaussianNB
from tld import get_tld, is_tld



def tip(eticheta):
    tipuri = {
        "benign": '0',
        "defacement": '1',
        "phishing":'2', 
        "malware":'3'
    }
    return tipuri[eticheta]

def get_domain_name(url):
    parsed_uri = urlparse(url)
    domain = '{uri.netloc}'.format(uri=parsed_uri)
    return domain

def get_url_length(url):
    """
    Given a URL, returns the length of the URL.
    """
    return len(url)

def get_num_subdomains(url):
    parsed_uri = urlparse(url)
    if parsed_uri.hostname:
        subdomains = parsed_uri.hostname.split('.')
        return len(subdomains) - 2
    else:
        return 0


def count_subdomains(url):
    parsed_uri = urlparse(url)
    subdomains = parsed_uri.hostname.split('.')
    return len(subdomains) - 2 if len(subdomains) > 2 else 0


def has_keyword(url, keyword):
    """
    Given a URL and a keyword, returns True if the keyword is present in the URL, False otherwise.
    """
    return keyword in url

def get_num_digits(url):
    """
    Given a URL, returns the number of digit characters in the URL.
    """
    return sum(c.isdigit() for c in url)

def get_num_letters(url):
    """
    Given a URL, returns the number of letter characters in the URL.
    """
    return sum(c.isalpha() for c in url)

#read and import data base 
data = pd.read_csv('malicious_phish.csv')



data['domain'] = data['url'].apply(get_domain_name)
data['num_subdomains'] = data['url'].apply(get_num_subdomains)
# data['keywords_found'] = data[url_column].apply(lambda x: keywords_in_url(keywords, x))
data['num_digits'] = data['url'].apply(get_num_digits)
data['num_letters'] = data['url'].apply(get_num_letters)
data['url_length'] = data['url'].apply(get_url_length)


feature = ['@','?','-','=','.','#','%','+','$','!','*',',','//']
for a in feature:
    data[a] = data['url'].apply(lambda i: i.count(a))

    

rem = {"Category": {"benign": 0, "defacement": 1, "phishing":2, "malware":3}}
data['Category'] = data['type']
data = data.replace(rem)


data.info()
print(data)


# data.to_csv('your_updated_file.csv', index=False)

# ##################







# data = pd.read_csv('your_updated_updated_file.csv')
# X = data.drop(['url','type','Category','domain'],axis=1)#,'type_code'
# y = data['Category']


# X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=2)



# models = [DecisionTreeClassifier,RandomForestClassifier,AdaBoostClassifier,KNeighborsClassifier,SGDClassifier,
#          ExtraTreesClassifier,GaussianNB,MLPClassifier]
# accuracy_test=[]
# for m in models:
#     print('#############################################')
#     print('######-Model =>\033[07m {} \033[0m'.format(m))
#     model_ = m()
#     model_.fit(X_train, y_train)
#     pred = model_.predict(X_test)
#     acc = accuracy_score(pred, y_test)
#     accuracy_test.append(acc)
#     print('Test Accuracy :\033[32m \033[01m {:.2f}% \033[30m \033[0m'.format(acc*100))



# with open('pickle_model', 'wb') as file:
#     pickle.dump(model, file)









# print(data)
# data.info()

# impartirea datelor in 90% date de antrenare si 10 % date de testare
# date_train = data.iloc[:586072,3:19].values #primele 586072 linii (train), coloana zero (date)
# date_test = data.iloc[586073:,3:19].values #primele 586072 linii (train), coloana zero (date)
# etichete_train = data.iloc[:586072, 20:21].values #linii de la 586072 pana la final (test), coloana unu (etichete)
# etichete_test = data.iloc[586073:, 20:21].values #linii de la 586072 pana la final (test), coloana unu (etichete)

# # print(date_train)

# #CREARE SI ANTRENARE MLP

# clf=neural_network.MLPClassifier(hidden_layer_sizes=(100), learning_rate_init=1, max_iter=200)
# clf.fit(date_train, etichete_train)

# #TESTARE MLP

# predictii=clf.predict(date_test)
# acc=0
# for i in range(10000):
#     if etichete_test[i]==predictii[i]:
#         acc=acc+1
# print('Acuratetea=' + str((acc/len(etichete_test))*100) + '%')