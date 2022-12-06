import aws_cdk as core
import aws_cdk.assertions as assertions

from new_cdk.new_cdk_stack import NewCdkStack

# example tests. To run these tests, uncomment this file along with the example
# resource in new_cdk/new_cdk_stack.py
def test_sqs_queue_created():
    app = core.App()
    stack = NewCdkStack(app, "new-cdk")
    template = assertions.Template.from_stack(stack)

#     template.has_resource_properties("AWS::SQS::Queue", {
#         "VisibilityTimeout": 300
#     })
