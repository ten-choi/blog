---
title: "ISP: The Interface Segregation Principle"
labels: ["Archive"]
published: true
date: 2023-05-11T16:12:35+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 166
tistoryUrl: "https://yeolceo.tistory.com/166"
tistoryCategory: ""
tistoryTags: []
tistoryPostedAt: "2023-05-11 16:12:35"
language: en
bloggerPostId: "7913989537003317696"
---
Topic: What Is ISP  

ISP: Interface Segregation Principle  
It's the principle that clients shouldn't depend on methods they don't use.

Let's use ChatGPT to make some sample code.  
Take a look at the first sample below.

Here's an interface with everything crammed into one place, without ISP.  
Any vehicle that uses this interface would have to implement every feature.  
But what if changeGear is only for stick shifts, not automatics?  
And what if my car is an automatic?  

You'd have to build parts into the car that it never uses.  
Think about it physically and it hits home much more.  

My car is an automatic, yet it got a changeGear feature it doesn't need.  
In the end, you get unnecessary dependencies and coupling.

```java
public interface Vehicle {
    void changeGear();
    void startEngine();
    void stopEngine();
    void accelerate();
    void brake();
    void turnLeft();
    void turnRight();
}
```

Now look at the second sample.  
It's clearly an example of applying the interface segregation principle.

```java
public interface Gear {
    void change();
}

public interface Engine {
    void start();
    void stop();
}

public interface Acceleratable {
    void accelerate();
}

public interface Brakeable {
    void brake();
}

public interface Turnable {
    void turnLeft();
    void turnRight();
}
```

Just by splitting the interfaces like this, if my car is an automatic, it doesn't need to implement Gear.  
In other words, it rules out problems that could come from manipulating gears in an automatic car.  

That explanation really lives up to the name ISP.

```java
public class Car implements Engine, Acceleratable, Brakeable, Turnable {
    @Override
    public void start() {
        // code to start the engine
    }

    @Override
    public void stop() {
        // code to stop the engine
    }

    @Override
    public void accelerate() {
        // code to accelerate
    }

    @Override
    public void brake() {
        // code to apply the brakes
    }

    @Override
    public void turnLeft() {
        // code to turn left
    }

    @Override
    public void turnRight() {
        // code to turn right
    }
}
```
