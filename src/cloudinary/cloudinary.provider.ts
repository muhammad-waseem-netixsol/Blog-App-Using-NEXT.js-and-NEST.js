import { v2 } from 'cloudinary';
import { CLOUDINARY } from './constants';
export const CloudinaryProvider = {
  provide: CLOUDINARY,
  useFactory: () => {
    return v2.config({
      cloud_name: "dcc9wdqvh",
      api_key: "462141787865991",
      api_secret: "vegzJuspaeyVsIf-9RQB3t_lUdE",
    });
  },
};