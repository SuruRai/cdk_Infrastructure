'''from aws_cdk import (
    # Duration,
    Stack,
    # aws_sqs as sqs,
)
from constructs import Construct

class NewCdkStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # The code that defines your stack goes here

        # example resource
        # queue = sqs.Queue(
        #     self, "NewCdkQueue",
        #     visibility_timeout=Duration.seconds(300),
        # )'''

import aws_cdk as cdk
import aws_cdk.aws_s3 as s3
import aws_cdk.aws_ec2 as ec2
import aws_cdk.aws_rds as rds
import aws_cdk.aws_elasticloadbalancingv2 as elbv2
from constructs import Construct
import aws_cdk.aws_sns as sns
import aws_cdk.aws_sns_subscriptions as sns_subscriptions
import aws_cdk.aws_sqs as sqs
import aws_cdk.aws_ssm as ssm
import aws_cdk.aws_cloudwatch as cloudwatch
import aws_cdk.aws_logs as logs
import aws_cdk.aws_events_targets as targets
import aws_cdk.aws_events as events
from aws_cdk.aws_events import Rule
class NewCdkStack(cdk.Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        VPC= ec2.CfnVPC(self, "MyVPC",
        cidr_block= "10.0.0.0/16",
        enable_dns_support= True,
        enable_dns_hostnames= True
        )

        cfn_internet_gateway = ec2.CfnInternetGateway(self, "MyCfnInternetGateway")
        cfn_internet_gateway.add_depends_on(VPC)

        cfn_vPCGateway_attachment = ec2.CfnVPCGatewayAttachment(self, "MyCfnVPCGatewayAttachment",
        vpc_id=VPC.ref,
        internet_gateway_id=cfn_internet_gateway.ref)

        public_subnet1 = ec2.CfnSubnet(self, "PublicSubnet1",
        vpc_id= VPC.ref,
        availability_zone="us-east-1a",
        cidr_block="10.0.1.0/24",
        map_public_ip_on_launch=True,
        )
        public_subnet1.add_depends_on(VPC)

        public_subnet2 = ec2.CfnSubnet(self, "PublicSubnet2",
        vpc_id= VPC.ref,
        availability_zone="us-east-1b",
        cidr_block="10.0.2.0/24",
        map_public_ip_on_launch=True,
        )
        public_subnet2.add_depends_on(VPC)
        cfn_public_route_table = ec2.CfnRouteTable(self, "MyCfnRouteTable1",
        vpc_id=VPC.ref,
        
        )
        cfn_public_route_table.add_depends_on(cfn_internet_gateway)
        cfn_public_route = ec2.CfnRoute(self, "PublicRoute",
        route_table_id=cfn_public_route_table.ref,
        destination_cidr_block="0.0.0.0/0",
        gateway_id=cfn_internet_gateway.ref,
        )
        cfn_public_subnet_route_table_association1 = ec2.CfnSubnetRouteTableAssociation(self, "MyCfnPublicSubnetRouteTableAssociation1",
            route_table_id=cfn_public_route_table.ref,
            subnet_id=public_subnet1.ref
        )
        cfn_public_subnet_route_table_association2 = ec2.CfnSubnetRouteTableAssociation(self, "MyCfnPublicSubnetRouteTableAssociation2",
            route_table_id=cfn_public_route_table.ref,
            subnet_id=public_subnet2.ref
        )
        private_subnet1 = ec2.CfnSubnet(self, "PrivateSubnet1",
        vpc_id= VPC.ref,
        availability_zone="us-east-1a",
        cidr_block="10.0.3.0/24",
        map_public_ip_on_launch=False,
        )
        private_subnet1.add_depends_on(VPC)
        private_subnet2 = ec2.CfnSubnet(self, "PrivateSubnet2",
        vpc_id= VPC.ref,
        availability_zone="us-east-1b",
        cidr_block="10.0.4.0/24",
        map_public_ip_on_launch=False,
        )
        private_subnet2.add_depends_on(VPC)
        elastic_ip = ec2.CfnEIP(self, "EIP",
        domain=VPC.ref
        )
        elastic_ip.add_depends_on(cfn_internet_gateway)
        cfn_nat_gateway = ec2.CfnNatGateway(self, "MyCfnNatGateway",
        subnet_id=public_subnet1.ref,
        allocation_id=elastic_ip.attr_allocation_id
        )
        cfn_nat_gateway.add_depends_on(elastic_ip)
        cfn_nat_gateway.add_depends_on(cfn_internet_gateway)
        cfn_private_route_table = ec2.CfnRouteTable(self, "PrivateRouteTable",
        vpc_id=VPC.ref,
        )
        cfn_nat_gateway.add_depends_on(cfn_nat_gateway)
        cfn_private_route = ec2.CfnRoute(self, "PrivateRoute",
        route_table_id=cfn_private_route_table.ref,
        destination_cidr_block="0.0.0.0/0",
        nat_gateway_id=cfn_nat_gateway.ref,
        )
        cfn_private_subnet_route_table_association1 = ec2.CfnSubnetRouteTableAssociation(self, "MyCfnPrivateSubnetRouteTableAssociation1",
            route_table_id=cfn_private_route_table.ref,
            subnet_id=private_subnet1.ref
        )
        cfn_private_subnet_route_table_association2 = ec2.CfnSubnetRouteTableAssociation(self, "MyCfnPrivateSubnetRouteTableAssociation2",
            route_table_id=cfn_private_route_table.ref,
            subnet_id=private_subnet2.ref
        )

        cfn_security_group_rds = ec2.CfnSecurityGroup(self, "MyCfnSecurityGrouprds",
            group_description="Security_Group_For_VPC",
            vpc_id=VPC.ref
        )
        cfn_security_group_egress_rds = ec2.CfnSecurityGroupEgress(self, "MyCfnSecurityGroupEgress_rds",
            ip_protocol="-1",
            cidr_ip="0.0.0.0/0",
            from_port=0,
            to_port=0,
            group_id=cfn_security_group_rds.ref
        )
        cfn_security_group_ingress_rds = ec2.CfnSecurityGroupIngress(self, "MyCfnSecurityGroupIngressRDS",
            ip_protocol="tcp",
            cidr_ip="10.0.0.0/16",
            from_port=3306,
            to_port=3306,
            group_id=cfn_security_group_rds.ref
        )

        cfn_dBSubnet_group = rds.CfnDBSubnetGroup(self, "MyCfnDBSubnetGroup",
            db_subnet_group_description="dbSubnet",
            subnet_ids=[private_subnet1.ref,private_subnet2.ref],
        )


        cfn_dBInstance = rds.CfnDBInstance(self, "MyCfnDBInstance",
            # allow_major_version_upgrade=False,
            # associated_roles=[rds.CfnDBInstance.DBInstanceRoleProperty(
            #     feature_name="s3Import",
            #     role_arn="arn:aws:iam::128680359488:role/RDSLoadFromS3"
            # )],
            db_name="crudapplication",
            deletion_protection=False,
            publicly_accessible=False,
            storage_encrypted=False,
            use_default_processor_features=False,
            master_username="Suruchi",
            master_user_password="123456789",
            db_instance_class="db.t2.micro",
            engine="mysql",
            engine_version="8.0.23",
            vpc_security_groups=[cfn_security_group_rds.ref],
            allocated_storage="10",
            db_subnet_group_name=cfn_dBSubnet_group.ref,
            db_instance_identifier="database-1"
        )
        cfn_dBInstance.add_depends_on(cfn_dBSubnet_group)


        cfn_security_group = ec2.CfnSecurityGroup(self, "MyCfnSecurityGroup",
            group_description="Security_Group_For_VPC",
            vpc_id=VPC.ref
        )
        cfn_security_group_egress = ec2.CfnSecurityGroupEgress(self, "MyCfnSecurityGroupEgress",
            ip_protocol="-1",
            cidr_ip="0.0.0.0/0",
            from_port=0,
            to_port=0,
            group_id=cfn_security_group.ref
        )
        cfn_security_group_ingress = ec2.CfnSecurityGroupIngress(self, "MyCfnSecurityGroupIngressMySql",
            ip_protocol="tcp",
            cidr_ip="0.0.0.0/0",
            from_port=3306,
            to_port=3306,
            group_id=cfn_security_group.ref
        )
        cfn_security_group_ingress = ec2.CfnSecurityGroupIngress(self, "MyCfnSecurityGroupIngressSSH",
            ip_protocol="tcp",
            cidr_ip="0.0.0.0/0",
            from_port=22,
            to_port=22,
            group_id=cfn_security_group.ref
        )
        cfn_security_group_ingress = ec2.CfnSecurityGroupIngress(self, "MyCfnSecurityGroupIngressHTTP",
            ip_protocol="tcp",
            cidr_ip="0.0.0.0/0",
            from_port=80,
            to_port=80,
            group_id=cfn_security_group.ref
        )
        cfn_security_group_ingress = ec2.CfnSecurityGroupIngress(self, "MyCfnSecurityGroupIngressHTTPS",
            ip_protocol="tcp",
            cidr_ip="0.0.0.0/0",
            from_port=443,
            to_port=443,
            group_id=cfn_security_group.ref
        )
        cfn_instance = ec2.CfnInstance(self, "MyCfnInstance",
        iam_instance_profile="ec2role",
        key_name="suruchi",
        image_id="ami-0b0dcb5067f052a63",
        instance_type="t2.micro",
        subnet_id=private_subnet1.ref,
        #subnet_id=public_subnet1.ref,
        security_group_ids=[cfn_security_group.ref],
        user_data=cdk.Fn.base64('''#!/bin/bash\nsudo yum update -y\nsudo yum install python3-pip git mysql -y\nsudo rpm -Uvh https://s3.amazonaws.com/amazoncloudwatch-agent/amazon_linux/amd64/latest/amazon-cloudwatch-agent.rpm\nsudo aws s3 cp s3://mybucket25059910/config.json /opt/aws/amazon-cloudwatch-agent/config.json\nsudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s -c file:/opt/aws/amazon-cloudwatch-agent/config.json\nsudo /bin/systemctl restart amazon-cloudwatch-agent.service\nsudo git clone "https://github.com/SuruRai/Crud.git"\nsudo pip3 install flask\nsudo yum -y install python python3-devel mysql-devel redhat-rpm-config gcc\nsudo pip3 install flask_mysqldb\nsudo pip3 install mysql-connector-python\nsudo pip3 install Werkzeug\ncd Crud\npython3 app.py\nsudo /bin/systemctl restart amazon-cloudwatch-agent.service''')
        #user_data=cdk.Fn.base64('''#!/bin/bash\nsudo su\nyum update -y\nyum install -y httpd\nsystemctl start httpd\nsystemctl enable httpd\necho "<h1>Hello World from $(hostname -f)</h1>" > /var/www/html/index.html''')

        )
        cfn_instance.add_depends_on(cfn_dBInstance)
        cfn_instance.add_depends_on(cfn_nat_gateway)

        cfn_volume = ec2.CfnVolume(self, "MyCfnVolume",
            availability_zone="us-east-1a",
            encrypted=False,
            size=8
        )
        cfn_volume.add_depends_on(cfn_instance)

        cfn_volume_attachment = ec2.CfnVolumeAttachment(self, "MyCfnVolumeAttachment",
            device="/dev/sdg",
            instance_id=cfn_instance.ref,
            volume_id=cfn_volume.ref
        )
        cfn_volume_attachment.add_depends_on(cfn_volume)

        cfn_target_group = elbv2.CfnTargetGroup(self, "MyCfnTargetGroup",
            health_check_enabled=True,
            health_check_interval_seconds=30,
            health_check_timeout_seconds=5,
            healthy_threshold_count=5,
            port=80,
            targets=[elbv2.CfnTargetGroup.TargetDescriptionProperty(
                id=cfn_instance.ref
            )],
            unhealthy_threshold_count=2,
            vpc_id=VPC.ref,
            protocol="HTTP",
            target_type="instance"
        )
        cfn_target_group.add_depends_on(cfn_instance)


        cfn_security_group_alb = ec2.CfnSecurityGroup(self, "MyCfnSecurityGrouplb",
            group_description="Security_Group_For_VPC",
            vpc_id=VPC.ref
        )
        cfn_security_group_egress = ec2.CfnSecurityGroupEgress(self, "MyCfnSecurityGroupEgress_alb",
            ip_protocol="-1",
            cidr_ip="0.0.0.0/0",
            from_port=0,
            to_port=0,
            group_id=cfn_security_group_alb.ref
        )
        cfn_security_group_ingress = ec2.CfnSecurityGroupIngress(self, "MyCfnSecurityGroupIngressHTTP_alb",
            ip_protocol="tcp",
            cidr_ip="0.0.0.0/0",
            from_port=80,
            to_port=80,
            group_id=cfn_security_group_alb.ref
        )
        cfn_load_balancer = elbv2.CfnLoadBalancer(self, "MyCfnLoadBalancer",
            name="MyLoadBalancer",
            scheme="internet-facing",
            security_groups=[cfn_security_group_alb.ref],
            subnets=[public_subnet2.ref,public_subnet1.ref],
            type="application"
        )
        cfn_load_balancer.add_depends_on(cfn_instance)
        cfn_listener = elbv2.CfnListener(self, "MyCfnListener",
            default_actions=[elbv2.CfnListener.ActionProperty(
                type="forward",
                forward_config=elbv2.CfnListener.ForwardConfigProperty(
                    target_groups=[elbv2.CfnListener.TargetGroupTupleProperty(
                        target_group_arn=cfn_target_group.ref,
                        weight=10
                    )],
                    target_group_stickiness_config=elbv2.CfnListener.TargetGroupStickinessConfigProperty(
                        duration_seconds=65,
                        enabled=False
                    )
                ),
                order=2,
            )],
            load_balancer_arn=cfn_load_balancer.ref,
            port=80,
            protocol="HTTP"
        )
        cfn_load_balancer.add_depends_on(cfn_instance)


        my_topic = sns.Topic(self, "Topic",display_name="MYSNS")

        cfn_subscription = sns.CfnSubscription(self, "MyCfnSubscription",
            protocol="email",
            topic_arn=my_topic.topic_arn,
            endpoint="rs250599@gmail.com"
        )


        cfn_alarm = cloudwatch.CfnAlarm(self, "MyCfnAlarm",
            alarm_name="Alarm",
            comparison_operator="GreaterThanOrEqualToThreshold",
            evaluation_periods=1,
            actions_enabled=False,
            datapoints_to_alarm=1,
            dimensions=[cloudwatch.CfnAlarm.DimensionProperty(
                name="ec2-instance",
                value="ec2-instance"
            )],
            period=900,
            threshold=30,
            statistic="Average",
            namespace="AWS/EC2",
            alarm_description="alert user if CPU touches 30%",
            metric_name="CPUUtilization",
            alarm_actions=[cfn_subscription.ref]
        )

        bucket = s3.Bucket(self, "MyFirstBucket", versioned=True)


