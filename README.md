# s3-permissions-blog-post

Access management is a key attribute to the security of any enterprise IT infrastructure. Amazon Web Services (AWS) offers a variety of tools to address access management. Having a wide variety of options available provides flexibility and agility to the customer but can also add confusion as it is sometimes unclear how these access management services interact. Specifically, S3 access management can get quite overwhelming. Object ACLs, Bucket ACLs, IAM Policies, Bucket Policies, Bucket Ownership, and Object Ownership all effect who has access to an object stored in S3 and it can be unclear how they interact.

When interacting with s3 permissions, [this AWS blog post](https://aws.amazon.com/blogs/security/iam-policies-and-bucket-policies-and-acls-oh-my-controlling-access-to-s3-resources/) is my goto for a basic understanding of the interactions between the three access controls (IAM policies, bucket policies, ACLs), but it doesn't cover every use case, notably it does not mention that the object owner can have an effect on the permissions.

In an attempt to add some clarity to the s3 permissions, we created a script to test all relevant combinations of IAM policy, bucket policy, object owner and ACL.