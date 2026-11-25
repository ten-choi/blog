---
title: "[ AWS ] Using Lambda and Deploying with SAM"
labels: ["Cloud","aws","SAM","lambda","Archive"]
published: true
date: 2022-07-01T15:49:56+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 136
tistoryUrl: "https://yeolceo.tistory.com/136"
tistoryCategory: "Cloud/aws"
tistoryTags: ["SAM","AWS","aws","lambda"]
tistoryPostedAt: "2022-07-01 15:49:56"
language: en
bloggerPostId: "5001996336767097433"
---
#### Environment

AWS Lambda  
Mac M1  
Node 16

#### Overview

Instead of editing Lambda directly in AWS, we'll write the code locally and deploy it with SAM.

#### Contents

-   What is SAM
-   Environment setup
-   Creating and deploying with SAM
-   Key config files explained
-   Test

## **\- What Is SAM**

SAM stands for Serverless Application Model. It's an open-source framework for building serverless applications (Lambda).

With the SAM CLI, you can handle Lambda's initial setup, build, and deployment.

## **\- Environment Setup**

Install [**aws-cli**](https://docs.aws.amazon.com/ko_kr/cli/latest/userguide/getting-started-install.html) and [**sam-cli**](https://docs.aws.amazon.com/ko_kr/serverless-application-model/latest/developerguide/serverless-sam-cli-install.html) on your machine. Finish the installation using those links or by searching.

Once that's done, create a test directory and try the sam command in the terminal.

Run both the aws-cli and sam-cli commands to make sure they're installed correctly.

The AWS CLI also has an authentication step, so go through all of it.

## **\- Creating and Deploying with SAM**

#### **1\. sam init**

Run sam init to do the initial SAM setup.

As shown in the image below, I picked option 1 from the quick start templates, Hello World Example. The next question asks you to choose a runtime; you have to answer N

to pick a different runtime. Choose node. If you type anything else, you'll get error invalid input like below.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/136/img.webp)

In the template below, I chose TypeScript. I'd guess option 1 is JS.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/136/img_1.webp)

For the rest of the SAM initial setup, read through each prompt and enter the defaults or press y. The project setup will finish and a directory will be created.

Now let's look at the files init generated. There's the code Lambda will run (currently app.js) and the config for how to set up and deploy Lambda (template.yaml).

If you analyze the template source while looking things up, SAM becomes easy to understand.

#### **2\. sam build**

Run sam build. If there are no problems with the template settings or the source, the build will go through fine.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/136/img_2.webp)

#### **3\. sam deploy -g**

If there are changes, build and then deploy. When you run sam deploy -g, it asks for things like the stack name and region. Usually

you can enter the defaults and answer y to the rest. Read the prompts as they come up and choose for yourself where needed.

## **\- Key Config Files Explained**

The function exported here is used in the template settings.

```dsconfig
import { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';

/**
 *
 * Event doc: https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html#api-gateway-simple-proxy-for-lambda-input-format
 * @param {Object} event - API Gateway Lambda Proxy Input Format
 *
 * Return doc: https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html
 * @returns {Object} object - API Gateway Lambda Proxy Output Format
 *
 */

export const lambdaHandler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
    let response: APIGatewayProxyResult;
    try {
        response = {
            statusCode: 200,
            body: JSON.stringify({
                message: 'hello world',
            }),
        };
    } catch (err) {
        console.log(err);
        response = {
            statusCode: 500,
            body: JSON.stringify({
                message: 'some error happened',
            }),
        };
    }

    return response;
};
```

You don't need to worry about things like AWSTemplateFormatVersion or Description.

Globals applies to every Lambda resource used in the project.

Resources is where each project's settings go. Looking them up one by one helps you understand them.

```bash
AWSTemplateFormatVersion: '2010-09-09'
Transform: AWS::Serverless-2016-10-31
Description: >
  sam-app

  Sample SAM Template for sam-app

# More info about Globals: https://github.com/awslabs/serverless-application-model/blob/master/docs/globals.rst
Globals:
  Function:
    Timeout: 3
    Tracing: Active

Resources:
  HelloWorldFunction:
    Type: AWS::Serverless::Function # More info about Function Resource: https://github.com/awslabs/serverless-application-model/blob/master/versions/2016-10-31.md#awsserverlessfunction
    Properties:
      CodeUri: hello-world/
      Handler: app.lambdaHandler
      Runtime: nodejs16.x
      Architectures:
        - x86_64
      Events:
        HelloWorld:
          Type: Api # More info about API Event Source: https://github.com/awslabs/serverless-application-model/blob/master/versions/2016-10-31.md#api
          Properties:
            Path: /hello
            Method: get
    Metadata: # Manage esbuild properties
      BuildMethod: esbuild
      BuildProperties:
        Minify: true
        Target: "es2020"
        Sourcemap: true
        EntryPoints: 
        - app.ts

Outputs:
  # ServerlessRestApi is an implicit API created out of Events key under Serverless::Function
  # Find out more about other implicit resources you can reference within SAM
  # https://github.com/awslabs/serverless-application-model/blob/master/docs/internals/generated_resources.rst#api
  HelloWorldApi:
    Description: "API Gateway endpoint URL for Prod stage for Hello World function"
    Value: !Sub "https://${ServerlessRestApi}.execute-api.${AWS::Region}.amazonaws.com/Prod/hello/"
  HelloWorldFunction:
    Description: "Hello World Lambda Function ARN"
    Value: !GetAtt HelloWorldFunction.Arn
  HelloWorldFunctionIamRole:
    Description: "Implicit IAM Role created for Hello World function"
    Value: !GetAtt HelloWorldFunctionRole.Arn
```

## **\-Test**

Testing itself is very simple. Go into AWS Lambda and test the code there, or just send a request to the URL and check the response, and you're done.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/136/img_3.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/136/img_4.webp)

Beyond the basic structure above, it'd be good to also test a case that includes DB queries and requests.

Happy coding, and keep at it.
