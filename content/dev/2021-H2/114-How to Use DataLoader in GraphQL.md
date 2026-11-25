---
title: "How to Use DataLoader in GraphQL"
labels: ["ETC","Graphql.js","graphql","DataLoader","Archive"]
published: true
date: 2021-12-20T11:06:46+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 114
tistoryUrl: "https://yeolceo.tistory.com/114"
tistoryCategory: "ETC/Graphql.js"
tistoryTags: ["graphql","데이터로더","graphql"]
tistoryPostedAt: "2021-12-20 11:06:46"
language: en
bloggerPostId: "6732947076462557780"
retitled: true
---
If you're going to use DataLoader in GraphQL, you should know why you're using it.

DataLoader is what you use when GraphQL resolves sub-queries.

Its job is batching. That naturally leads to the question: why do sub-queries need to be batched? Let's first look at what goes wrong without batching.

### **The GraphQL N+1 Problem Without Batching**

Here's an example of using sub-queries in GraphQL.

EX) Say we have a grades table A and a user info table B.  
Table A has a column called B\_id, which is the PK of table B.  
Now let's start fetching data.

Assume we fetch 5 rows from table A over a single connection by specifying a range. Then we use a GraphQL sub-query to fetch table B's info by B\_id. The B\_id of each of the 5 rows returned from table A is fetched separately. In this case, we need as many DB connections as there are rows.  
1 connection for table A + 5 for table B (one per row). Scale that to 100 or 1,000,000 rows and you end up with 1,000,000 DB connections, which wastes resources.

### **What Is DataLoader**

It's a library that solves the N+1 problem when fetching GraphQL data by using batching.

Fetching data through a GraphQL sub-query means using table A's key values to get values from table B, and DataLoader is the library that handles this pattern efficiently.  
Let's look at its main features.

**1\. Batching**

Here's the process when GraphQL fetches data through a sub-query. When the API is called, a query returns data. A sub-query uses one of the returned fields as a key to run a new query, and returns the sub-query's data in place of that key. DataLoader collects the keys the sub-query will use into an array via the load function and passes them to the DataLoader function. It then returns the objects fetched with those keys according to two conditions: it must return an array the same length as the key array, and each object fetched by a key must sit in the matching position, i.e. the same index as its key.

**2\. Caching**

A cache is created for each function called through DataLoader; it has its own CacheMap internally. Once the cache exists, repeated identical calls return values from memory instead of hitting the DB, which cuts resource waste. However, if the parameters of the API being called change often, it can keep mapping lots of cache entries, which can be wasteful too. Use it with that in mind, or consider turning off caching.

### Usage

First spin up a Node server and run the source, then walk through it following the logic.

```html
import { ApolloServer, gql } from "apollo-server"; // add the GraphQL server
// import { ApolloServer } from "apollo-server-express"; 
import DataLoader from "dataloader"; // add DataLoader
let port = '4001'; // port

// user data
const users = [
    {
      id: 1,
      name: 'chan',
      age: 19,
    },
    {
      id: 2,
      name: 'yeong',
      age: 20,
    },
    {
      id: 3,
      name: 'cho',
      age: 21,
    },
  ];
  // post data
  const posts = [
    {
      id: 1,
      title: 'test post title 1',
      contents: 'test content',
      user: 1,
    },
    {
      id: 2,
      title: 'test post title 2',
      contents: 'test content',
      user: 2,
    },
    {
      id: 3,
      title: 'test post title 3',
      contents: 'test content',
      user: 3,
    },
    {
      id: 4,
      titles: 'test post title 4',
      content: 'test content',
      user: 3,
    },
    {
      id: 5,
      title: 'test post title 5',
      contents: 'test content',
      user: 1,
    },
  ];

// GraphQL type definitions
const typeDefs = gql`
    type User{
        id:Int
        name:String
        age:Int
    }

    type Post{
        id:Int
        title:String
        contents:String
        user:User
    }

    type Query{
        posts:[Post]
    }
`;

// GraphQL sub-query
const getUsers = (ids) => {
    return new Promise(
        (res) => 
         res(users.filter(
                (user) => ids.includes(user.id)
            )
        )
    );
  };

  // receives the keys collected by each dataloader.load call as an array and requests the data
  const batchGetUser = new DataLoader(async (keys) => {
  	
    // fetch users by key
    const _users = await getUsers(keys);

    const usersMap = {}; // create an object
    // store in usersMap with user id as key and user info as value
    _users.forEach((user) => (usersMap[user.id] = user));
    // return it if the id exists

    return keys.map((id) => usersMap[id] || null); // return the data if it exists in the array
}, {
	// cache set to false for testing; otherwise it serves from cache and skips the logic
    cache: false 
});

 // resolvers
  const resolvers = {
    Query: {
      // Data Fetcher
      posts: async () => {
        const copiedPosts = JSON.parse(JSON.stringify(posts));
        const result = copiedPosts.map((post) => {
          post.user =  batchGetUser.load(post.user);
          return post;
        });

        return result;
      },
    },
  };

const server = new ApolloServer({ typeDefs, resolvers }); // register the server
// start the server
server.listen(port).then( ({ url }) => console.log(`server ready at ${url}`));
```

**The query to call from the web**

```html
// query to use when calling http://localhost:4001/graphql
query{

  posts{
     id
     title
     contents 
     user{
           id
           name
           age
     }
  }

}
```

**The query rewritten to fetch from a DB**

```html
async function getUsers(user) {
    try {
        if (!user) return [];
        let inArrayAll = [];
        // collect the id values to put into IN
        user.map((id)=>inArrayAll = [...inArrayAll, JSON.stringify(id)] );
 		
        // join them together nicely
        const queryString =
            "SELECT  * FROM USERS_INFO WHERE ( userId ) in (" + inArrayAll.join() + ")";

        let results = await db.exe(queryString);

        return results;
    } catch (err) {
        logger.error(": " + err);
        throw new Error(err);
    }
}
```

It fetches the data with the key values in a single IN (OR) query. Fewer DB connections means better performance, and since the fetched data is cached, fetching the same data again costs less.

Nice work. Happy coding.

References

[https://chanyeong.com/blog/post/53](https://chanyeong.com/blog/post/53)
