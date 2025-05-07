import mongoose from 'mongoose';
import bcrypt from 'bcrypt';

const companySchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    password: String,
});

companySchema.pre('save', async function () {
    if (!this.isModified('password')) return;
    this.password = await bcrypt.hash(this.password, 10);
});

export default mongoose.model('Company', companySchema);